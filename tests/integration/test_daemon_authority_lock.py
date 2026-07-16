"""F3 daemon mutable-authority admission regressions."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import queue
import socket
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from shisad.core.api.transport import ControlClient, ControlServer
from shisad.core.authority import (
    AuthorityClaimError,
    AuthorityConflictError,
    AuthorityRegistryError,
    DaemonAuthorityClaim,
    acquire_daemon_authority_claim,
    derive_daemon_authority_candidates,
    initialize_claimed_daemon_authorities,
)
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from shisad.daemon.services import DaemonServices
from tests.helpers.daemon import clear_remote_provider_env
from tests.helpers.daemon import wait_for_socket as _wait_for_socket


def _hold_authority_claim(
    data_dir: str,
    socket_path: str,
    policy_path: str,
    ready: Any,
    release: Any,
    outcome: Any,
) -> None:
    config = DaemonConfig(
        data_dir=Path(data_dir),
        socket_path=Path(socket_path),
        policy_path=Path(policy_path),
    )
    try:
        claim = acquire_daemon_authority_claim(config)
    except BaseException as exc:
        outcome.put(f"error:{type(exc).__name__}:{exc}")
        ready.set()
        return
    outcome.put("claimed")
    ready.set()
    release.wait(timeout=10)
    claim.release()


def _config(tmp_path: Path, *, name: str, socket_name: str) -> DaemonConfig:
    return DaemonConfig(
        data_dir=tmp_path / name / "data",
        socket_path=tmp_path / socket_name,
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )


def test_f3_authority_candidates_are_complete_and_side_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval_path = tmp_path / "approval-parent" / "factors.json"
    soul_path = tmp_path / "soul-parent" / "SOUL.md"
    monkeypatch.setenv("SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH", str(approval_path))
    config = DaemonConfig(
        data_dir=tmp_path / "data-parent" / "data",
        socket_path=tmp_path / "socket-parent" / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        assistant_persona_soul_path=soul_path,
    )

    candidates = derive_daemon_authority_candidates(config)

    assert {candidate.role for candidate in candidates} == {
        "approval_factor_store",
        "control_socket",
        "data_root",
        "soul",
    }
    assert {candidate.path for candidate in candidates} == {
        approval_path,
        config.data_dir,
        config.socket_path,
        soul_path,
    }
    assert not approval_path.parent.exists()
    assert not config.data_dir.parent.exists()
    assert not config.socket_path.parent.exists()
    assert not soul_path.parent.exists()


@pytest.mark.parametrize("overlap", ["exact", "ancestor", "socket"])
def test_f3_candidate_cannot_overlap_host_global_registry(
    tmp_path: Path,
    overlap: str,
) -> None:
    registry_root = Path("/tmp") / f"shisad-authority-{os.getuid()}"
    data_dir = tmp_path / "data"
    socket_path = tmp_path / "control.sock"
    if overlap == "exact":
        data_dir = registry_root
    elif overlap == "ancestor":
        data_dir = registry_root.parent
    else:
        socket_path = registry_root / "control.sock"
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=socket_path,
        policy_path=tmp_path / "policy.yaml",
    )

    with pytest.raises(AuthorityRegistryError, match="overlaps host-global registry"):
        acquire_daemon_authority_claim(config)


def test_f3_atomic_claim_loser_cannot_create_or_repair_target(tmp_path: Path) -> None:
    data_dir = tmp_path / "shared" / "data"
    data_dir.mkdir(parents=True, mode=0o755)
    marker = data_dir / "marker"
    marker.write_text("winner-only", encoding="utf-8")
    before = data_dir.stat()
    winner_config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "winner.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    loser_config = winner_config.model_copy(update={"socket_path": tmp_path / "loser.sock"})

    winner_claim = acquire_daemon_authority_claim(winner_config)
    try:
        with pytest.raises(AuthorityConflictError, match="data_root"):
            acquire_daemon_authority_claim(loser_config)

        after_loser = data_dir.stat()
        assert (after_loser.st_ino, after_loser.st_mode, after_loser.st_mtime_ns) == (
            before.st_ino,
            before.st_mode,
            before.st_mtime_ns,
        )
        assert marker.read_text(encoding="utf-8") == "winner-only"

        initialize_claimed_daemon_authorities(winner_config, winner_claim)
        assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
    finally:
        winner_claim.release()

    successor_claim = acquire_daemon_authority_claim(loser_config)
    successor_claim.release()


def test_f3_disjoint_authority_claims_can_coexist(tmp_path: Path) -> None:
    config_a = _config(tmp_path, name="a", socket_name="a.sock")
    config_b = _config(tmp_path, name="b", socket_name="b.sock")

    claim_a = acquire_daemon_authority_claim(config_a)
    try:
        claim_b = acquire_daemon_authority_claim(config_b)
        try:
            initialize_claimed_daemon_authorities(config_a, claim_a)
            initialize_claimed_daemon_authorities(config_b, claim_b)
            assert config_a.data_dir.is_dir()
            assert config_b.data_dir.is_dir()
        finally:
            claim_b.release()
    finally:
        claim_a.release()


def test_f3_simultaneous_overlapping_authority_admission_has_one_winner(
    tmp_path: Path,
) -> None:
    config_a = _config(tmp_path, name="shared", socket_name="a.sock")
    config_b = _config(tmp_path, name="shared", socket_name="b.sock")
    barrier = threading.Barrier(2)
    allow_release = threading.Event()
    outcomes: queue.Queue[tuple[str, object]] = queue.Queue()

    def _contend(config: DaemonConfig) -> None:
        barrier.wait(timeout=3)
        try:
            claim = acquire_daemon_authority_claim(config)
        except AuthorityConflictError as exc:
            outcomes.put(("conflict", exc))
            return
        outcomes.put(("claimed", claim))
        allow_release.wait(timeout=3)
        claim.release()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_contend, config) for config in (config_a, config_b)]
        first = outcomes.get(timeout=3)
        second = outcomes.get(timeout=3)
        assert sorted((first[0], second[0])) == ["claimed", "conflict"]
        assert not config_a.data_dir.parent.exists()
        allow_release.set()
        for future in futures:
            future.result(timeout=3)


def test_f3_simultaneous_disjoint_authority_admission_allows_both(
    tmp_path: Path,
) -> None:
    config_a = _config(tmp_path, name="a", socket_name="a.sock")
    config_b = _config(tmp_path, name="b", socket_name="b.sock")
    barrier = threading.Barrier(2)
    allow_release = threading.Event()
    outcomes: queue.Queue[DaemonAuthorityClaim] = queue.Queue()

    def _contend(config: DaemonConfig) -> None:
        barrier.wait(timeout=3)
        claim = acquire_daemon_authority_claim(config)
        outcomes.put(claim)
        allow_release.wait(timeout=3)
        claim.release()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_contend, config) for config in (config_a, config_b)]
        claims = [outcomes.get(timeout=3), outcomes.get(timeout=3)]
        assert len(claims) == 2
        assert not config_a.data_dir.parent.exists()
        assert not config_b.data_dir.parent.exists()
        allow_release.set()
        for future in futures:
            future.result(timeout=3)


def test_f3_authority_claim_is_host_global_across_processes(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    outcome = context.Queue()
    winner_config = _config(tmp_path, name="shared", socket_name="winner.sock")
    loser_config = winner_config.model_copy(update={"socket_path": tmp_path / "loser.sock"})
    process = context.Process(
        target=_hold_authority_claim,
        args=(
            str(winner_config.data_dir),
            str(winner_config.socket_path),
            str(winner_config.policy_path),
            ready,
            release,
            outcome,
        ),
    )
    process.start()
    try:
        assert ready.wait(timeout=5)
        assert outcome.get(timeout=5) == "claimed"
        with pytest.raises(AuthorityConflictError, match="data_root"):
            acquire_daemon_authority_claim(loser_config)
        assert not winner_config.data_dir.parent.exists()
    finally:
        release.set()
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join(timeout=3)
    assert process.exitcode == 0

    successor_claim = acquire_daemon_authority_claim(loser_config)
    successor_claim.release()


@pytest.mark.asyncio
async def test_f3_second_daemon_same_data_dir_fails_without_disturbing_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    winner_config = _config(tmp_path, name="shared", socket_name="winner.sock")
    loser_config = winner_config.model_copy(update={"socket_path": tmp_path / "loser.sock"})
    winner_task = asyncio.create_task(run_daemon(winner_config))
    client = ControlClient(winner_config.socket_path)

    try:
        await _wait_for_socket(winner_config.socket_path)
        await client.connect()
        with pytest.raises(AuthorityConflictError, match="data_root"):
            await run_daemon(loser_config)
        assert not loser_config.socket_path.exists()
        status = await client.call("daemon.status")
        assert status["status"] == "running"
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(winner_task, timeout=3)


@pytest.mark.asyncio
async def test_f3_failed_service_construction_releases_complete_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    config = _config(tmp_path, name="failed", socket_name="failed.sock").model_copy(
        update={"matrix_enabled": True}
    )

    with pytest.raises(ValueError, match="Matrix channel is enabled"):
        await DaemonServices.build(config)

    successor_claim = acquire_daemon_authority_claim(config)
    successor_claim.release()


@pytest.mark.asyncio
async def test_f3_cancelled_service_admission_releases_late_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.daemon import services as services_module

    config = _config(tmp_path, name="cancelled", socket_name="cancelled.sock")
    entered = threading.Event()
    proceed = threading.Event()
    real_acquire = acquire_daemon_authority_claim

    def _slow_acquire(run_config: DaemonConfig) -> DaemonAuthorityClaim:
        entered.set()
        assert proceed.wait(timeout=5)
        return real_acquire(run_config)

    monkeypatch.setattr(
        services_module,
        "acquire_daemon_authority_claim",
        _slow_acquire,
    )
    build_task = asyncio.create_task(DaemonServices.build(config))
    assert await asyncio.to_thread(entered.wait, 3)
    build_task.cancel()
    await asyncio.sleep(0)
    build_task.cancel()
    await asyncio.sleep(0.05)
    assert not build_task.done()
    proceed.set()

    with pytest.raises(asyncio.CancelledError):
        await build_task

    successor_claim = acquire_daemon_authority_claim(config)
    successor_claim.release()


@pytest.mark.asyncio
async def test_f3_repeated_cancellation_waits_for_initialization_before_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.daemon import services as services_module

    config = _config(tmp_path, name="initializing", socket_name="initializing.sock")
    entered = threading.Event()
    allow_finish = threading.Event()
    real_initialize = initialize_claimed_daemon_authorities

    def _slow_initialize(
        run_config: DaemonConfig,
        claim: DaemonAuthorityClaim,
    ) -> None:
        entered.set()
        assert allow_finish.wait(timeout=5)
        real_initialize(run_config, claim)

    monkeypatch.setattr(
        services_module,
        "initialize_claimed_daemon_authorities",
        _slow_initialize,
    )
    build_task = asyncio.create_task(DaemonServices.build(config))
    assert await asyncio.to_thread(entered.wait, 3)
    build_task.cancel()
    await asyncio.sleep(0)
    build_task.cancel()
    await asyncio.sleep(0.05)
    assert not build_task.done()
    allow_finish.set()

    with pytest.raises(asyncio.CancelledError):
        await build_task

    successor_claim = acquire_daemon_authority_claim(config)
    successor_claim.release()


@pytest.mark.asyncio
async def test_f3_repeated_cancellation_waits_for_error_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, name="error-release", socket_name="error-release.sock")
    entered = threading.Event()
    allow_release = threading.Event()
    real_release = DaemonAuthorityClaim.release

    async def _fail_build(
        _cls: type[DaemonServices],
        _config: DaemonConfig,
        *,
        authority_claim: DaemonAuthorityClaim,
    ) -> DaemonServices:
        del authority_claim
        raise RuntimeError("service construction failed")

    def _slow_release(claim: DaemonAuthorityClaim) -> None:
        entered.set()
        assert allow_release.wait(timeout=5)
        real_release(claim)

    monkeypatch.setattr(DaemonServices, "_build_claimed", classmethod(_fail_build))
    monkeypatch.setattr(DaemonAuthorityClaim, "release", _slow_release)
    build_task = asyncio.create_task(DaemonServices.build(config))
    assert await asyncio.to_thread(entered.wait, 3)
    build_task.cancel()
    await asyncio.sleep(0)
    build_task.cancel()
    await asyncio.sleep(0.05)
    assert not build_task.done()
    allow_release.set()

    with pytest.raises(RuntimeError, match="service construction failed"):
        await build_task

    successor_claim = acquire_daemon_authority_claim(config)
    successor_claim.release()


@pytest.mark.asyncio
async def test_f3_repeated_cancellation_waits_for_shutdown_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, name="shutdown", socket_name="shutdown.sock")
    claim = acquire_daemon_authority_claim(config)
    services = object.__new__(DaemonServices)
    services.authority_claim = claim
    entered = threading.Event()
    allow_release = threading.Event()
    real_release = DaemonAuthorityClaim.release

    def _slow_release(active_claim: DaemonAuthorityClaim) -> None:
        entered.set()
        assert allow_release.wait(timeout=5)
        real_release(active_claim)

    monkeypatch.setattr(DaemonAuthorityClaim, "release", _slow_release)
    shutdown_task = asyncio.create_task(services.shutdown())
    assert await asyncio.to_thread(entered.wait, 3)
    shutdown_task.cancel()
    await asyncio.sleep(0)
    shutdown_task.cancel()
    await asyncio.sleep(0.05)
    assert not shutdown_task.done()
    allow_release.set()

    with pytest.raises(asyncio.CancelledError):
        await shutdown_task

    successor_claim = acquire_daemon_authority_claim(config)
    successor_claim.release()


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["approval", "server"])
@pytest.mark.parametrize("outcome", ["failure", "cancellation"])
async def test_f3_daemon_startup_boundary_always_releases_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    outcome: str,
) -> None:
    clear_remote_provider_env(monkeypatch)
    config = _config(
        tmp_path,
        name="d",
        socket_name="r.sock",
    )
    services = await DaemonServices.build(config)
    entered = asyncio.Event()

    async def _return_services(
        _cls: type[DaemonServices],
        _config: DaemonConfig,
    ) -> DaemonServices:
        return services

    async def _approval_start() -> None:
        if boundary != "approval":
            return
        entered.set()
        if outcome == "failure":
            raise RuntimeError("approval startup failed")
        await asyncio.Event().wait()

    async def _server_start() -> None:
        if boundary != "server":
            return
        entered.set()
        if outcome == "failure":
            raise RuntimeError("server startup failed")
        await asyncio.Event().wait()

    monkeypatch.setattr(DaemonServices, "build", classmethod(_return_services))
    monkeypatch.setattr(services.approval_web, "start", _approval_start)
    monkeypatch.setattr(services.server, "start", _server_start)

    try:
        if outcome == "failure":
            with pytest.raises(RuntimeError, match=f"{boundary} startup failed"):
                await run_daemon(config)
        else:
            daemon_task = asyncio.create_task(run_daemon(config))
            await asyncio.wait_for(entered.wait(), timeout=3)
            daemon_task.cancel()
            await asyncio.sleep(0)
            daemon_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await daemon_task

        successor_claim = acquire_daemon_authority_claim(config)
        successor_claim.release()
    finally:
        if not services.authority_claim.released:
            await services.shutdown()


def test_f3_same_config_rejects_exact_cross_role_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared = tmp_path / "shared.json"
    monkeypatch.setenv("SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH", str(shared))
    config = _config(tmp_path, name="data", socket_name="shared.json")
    claim: DaemonAuthorityClaim | None = None
    try:
        with pytest.raises(AuthorityConflictError, match="cross-role"):
            claim = acquire_daemon_authority_claim(config)
    finally:
        if claim is not None:
            claim.release()


def test_f3_same_config_rejects_base_to_derived_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval_path = tmp_path / "approval.json"
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(approval_path),
    )
    config = _config(tmp_path, name="data", socket_name="approval.json.tmp")
    claim: DaemonAuthorityClaim | None = None
    try:
        with pytest.raises(AuthorityConflictError, match="derived"):
            claim = acquire_daemon_authority_claim(config)
    finally:
        if claim is not None:
            claim.release()


def test_f3_same_config_rejects_derived_to_derived_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(tmp_path / ".SOUL.md.stage"),
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        assistant_persona_soul_path=tmp_path / "SOUL.md",
    )
    claim: DaemonAuthorityClaim | None = None
    try:
        with pytest.raises(AuthorityConflictError, match="derived"):
            claim = acquire_daemon_authority_claim(config)
    finally:
        if claim is not None:
            claim.release()


@pytest.mark.parametrize("surface", ["policy", "signers"])
def test_f3_trusted_read_input_cannot_overlap_mutable_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    approval_path = tmp_path / "approval"
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(approval_path),
    )
    policy_path = tmp_path / "policy.yaml"
    signers_path = tmp_path / "allowed_signers"
    if surface == "policy":
        policy_path = tmp_path / "data" / "policy.yaml"
    else:
        signers_path = tmp_path / "approval.corrupt.allowed_signers"
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        selfmod_allowed_signers_path=signers_path,
    )
    claim: DaemonAuthorityClaim | None = None
    try:
        with pytest.raises(AuthorityConflictError, match="trusted read input"):
            claim = acquire_daemon_authority_claim(config)
    finally:
        if claim is not None:
            claim.release()


def test_f3_cross_claim_rejects_ancestor_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root = tmp_path / "first"
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(first_root / "approval.json"),
    )
    first = DaemonConfig(
        data_dir=first_root,
        socket_path=tmp_path / "first.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    first_claim = acquire_daemon_authority_claim(first)
    second_claim: DaemonAuthorityClaim | None = None
    try:
        monkeypatch.setenv(
            "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
            str(tmp_path / "second-approval.json"),
        )
        second = DaemonConfig(
            data_dir=tmp_path / "second",
            socket_path=first_root / "nested.sock",
            policy_path=tmp_path / "policy.yaml",
        )
        with pytest.raises(AuthorityConflictError, match="overlaps"):
            second_claim = acquire_daemon_authority_claim(second)
    finally:
        if second_claim is not None:
            second_claim.release()
        first_claim.release()


def test_f3_cross_claim_rejects_derived_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval_path = tmp_path / "approval.json"
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(approval_path),
    )
    first = _config(tmp_path, name="first", socket_name="first.sock")
    first_claim = acquire_daemon_authority_claim(first)
    second_claim: DaemonAuthorityClaim | None = None
    try:
        monkeypatch.setenv(
            "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
            str(tmp_path / "second-approval.json"),
        )
        second = _config(
            tmp_path,
            name="second",
            socket_name="approval.json.corrupt.retained",
        )
        with pytest.raises(AuthorityConflictError, match="overlaps"):
            second_claim = acquire_daemon_authority_claim(second)
    finally:
        if second_claim is not None:
            second_claim.release()
        first_claim.release()


@pytest.mark.parametrize(
    ("role", "expected_role"),
    [
        ("socket", "control_socket"),
        ("approval", "approval_factor_store"),
        ("soul", "soul"),
    ],
)
def test_f3_disjoint_data_roots_cannot_share_external_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    expected_role: str,
) -> None:
    shared = tmp_path / "shared"
    first_approval = shared if role == "approval" else tmp_path / "first-approval"
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(first_approval),
    )
    first = DaemonConfig(
        data_dir=tmp_path / "first",
        socket_path=shared if role == "socket" else tmp_path / "first.sock",
        policy_path=tmp_path / "policy.yaml",
        assistant_persona_soul_path=tmp_path / "SOUL.md" if role == "soul" else None,
    )
    first_claim = acquire_daemon_authority_claim(first)
    second_claim: DaemonAuthorityClaim | None = None
    try:
        second_approval = shared if role == "approval" else tmp_path / "second-approval"
        monkeypatch.setenv(
            "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
            str(second_approval),
        )
        second = DaemonConfig(
            data_dir=tmp_path / "second",
            socket_path=shared if role == "socket" else tmp_path / "second.sock",
            policy_path=tmp_path / "policy.yaml",
            assistant_persona_soul_path=(tmp_path / "SOUL.md" if role == "soul" else None),
        )
        with pytest.raises(AuthorityConflictError, match=expected_role):
            second_claim = acquire_daemon_authority_claim(second)
    finally:
        if second_claim is not None:
            second_claim.release()
        first_claim.release()


@pytest.mark.parametrize("reverse", [False, True])
def test_f3_cross_claim_rejects_derived_to_derived_in_either_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reverse: bool,
) -> None:
    paths = [tmp_path / "approval", tmp_path / ".approval.stage"]
    if reverse:
        paths.reverse()
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(paths[0]),
    )
    first = _config(tmp_path, name="first", socket_name="first.sock")
    first_claim = acquire_daemon_authority_claim(first)
    second_claim: DaemonAuthorityClaim | None = None
    try:
        monkeypatch.setenv(
            "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
            str(paths[1]),
        )
        second = _config(tmp_path, name="second", socket_name="second.sock")
        with pytest.raises(AuthorityConflictError, match="derived"):
            second_claim = acquire_daemon_authority_claim(second)
    finally:
        if second_claim is not None:
            second_claim.release()
        first_claim.release()


def test_f3_active_claim_refreshes_replaced_inode_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval_path = tmp_path / "approval.json"
    approval_path.write_text("old", encoding="utf-8")
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(approval_path),
    )
    first = _config(tmp_path, name="first", socket_name="first.sock")
    first_claim = acquire_daemon_authority_claim(first)
    second_claim: DaemonAuthorityClaim | None = None
    try:
        replacement = tmp_path / "replacement"
        replacement.write_text("new", encoding="utf-8")
        os.replace(replacement, approval_path)
        alias_path = tmp_path / "approval-alias.json"
        os.link(approval_path, alias_path)

        monkeypatch.setenv(
            "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
            str(alias_path),
        )
        second = _config(tmp_path, name="second", socket_name="second.sock")
        with pytest.raises(AuthorityConflictError, match="overlaps"):
            second_claim = acquire_daemon_authority_claim(second)
    finally:
        if second_claim is not None:
            second_claim.release()
        first_claim.release()


def test_f3_disjoint_sibling_authorities_both_succeed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(tmp_path / "first.json"),
    )
    first = _config(tmp_path, name="first", socket_name="first.sock")
    first_claim = acquire_daemon_authority_claim(first)
    second_claim: DaemonAuthorityClaim | None = None
    try:
        monkeypatch.setenv(
            "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
            str(tmp_path / "second.json"),
        )
        second = _config(tmp_path, name="second", socket_name="second.sock")
        second_claim = acquire_daemon_authority_claim(second)
    finally:
        if second_claim is not None:
            second_claim.release()
        first_claim.release()


@pytest.mark.parametrize(
    "surface",
    ["data", "socket", "policy", "approval", "soul", "signers"],
)
def test_f3_assistant_root_preflights_protected_control_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    surface: str,
) -> None:
    workspace = tmp_path / "workspace"
    control = tmp_path / "control"
    data_dir = control / "data"
    socket_path = control / "control.sock"
    policy_path = control / "policy.yaml"
    approval_path = control / "approval.json"
    soul_path: Path | None = None
    signers_path = control / "allowed_signers"
    if surface == "data":
        data_dir = workspace / "data"
    elif surface == "socket":
        socket_path = workspace / "control.sock"
    elif surface == "policy":
        policy_path = workspace / "policy.yaml"
    elif surface == "approval":
        approval_path = workspace / "approval.json"
    elif surface == "soul":
        soul_path = workspace / "SOUL.md"
    else:
        signers_path = workspace / "allowed_signers"
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(approval_path),
    )
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=socket_path,
        policy_path=policy_path,
        selfmod_allowed_signers_path=signers_path,
        assistant_persona_soul_path=soul_path,
        assistant_fs_roots=[workspace],
    )
    with caplog.at_level("WARNING", logger="shisad.core.authority"):
        claim = acquire_daemon_authority_claim(config)
    claim.release()
    assert "direct filesystem writes must remain blocked" in caplog.text


def test_f3_claimed_external_authorities_are_owner_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval_path = tmp_path / "approval.json"
    corrupt_path = tmp_path / "approval.json.corrupt.retained"
    soul_path = tmp_path / "SOUL.md"
    for path in (approval_path, corrupt_path, soul_path):
        path.write_text("state", encoding="utf-8")
        path.chmod(0o666)
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(approval_path),
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        assistant_persona_soul_path=soul_path,
    )

    claim = acquire_daemon_authority_claim(config)
    try:
        initialize_claimed_daemon_authorities(config, claim)
        for path in (approval_path, corrupt_path, soul_path):
            assert stat.S_IMODE(path.lstat().st_mode) == 0o600
    finally:
        claim.release()


def test_f3_symlinked_external_authority_fails_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target.json"
    target.write_text("trusted", encoding="utf-8")
    approval_path = tmp_path / "approval.json"
    approval_path.symlink_to(target)
    before = target.stat()
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(approval_path),
    )
    config = _config(tmp_path, name="data", socket_name="control.sock")
    claim: DaemonAuthorityClaim | None = None
    try:
        with pytest.raises(AuthorityRegistryError, match="symlink"):
            claim = acquire_daemon_authority_claim(config)
    finally:
        if claim is not None:
            claim.release()
    after = target.stat()
    assert (after.st_ino, after.st_mode, after.st_mtime_ns, target.read_bytes()) == (
        before.st_ino,
        before.st_mode,
        before.st_mtime_ns,
        b"trusted",
    )


def test_f3_symlinked_external_parent_fails_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_parent = tmp_path / "target-parent"
    target_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(target_parent, target_is_directory=True)
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(linked_parent / "approval.json"),
    )
    config = _config(tmp_path, name="data", socket_name="control.sock")

    with pytest.raises(AuthorityRegistryError, match="symlink ancestry"):
        acquire_daemon_authority_claim(config)
    assert list(target_parent.iterdir()) == []


def test_f3_symlinked_socket_parent_fails_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_parent = tmp_path / "target-parent"
    target_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(target_parent, target_is_directory=True)
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(tmp_path / "approval.json"),
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=linked_parent / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    with pytest.raises(AuthorityRegistryError, match=r"control_socket.*symlink ancestry"):
        acquire_daemon_authority_claim(config)
    assert list(target_parent.iterdir()) == []


def test_f3_external_authority_rejects_foreign_owner_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.core import authority as authority_module

    approval_path = tmp_path / "approval.json"
    approval_path.write_text("trusted", encoding="utf-8")
    monkeypatch.setenv(
        "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
        str(approval_path),
    )
    config = _config(tmp_path, name="data", socket_name="control.sock")
    current_uid = os.getuid()
    monkeypatch.setattr(authority_module.os, "getuid", lambda: current_uid + 1)

    with pytest.raises(AuthorityRegistryError, match="not owner-controlled"):
        derive_daemon_authority_candidates(config)


@pytest.mark.asyncio
async def test_f3_non_socket_control_path_fails_before_data_initialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    socket_path = tmp_path / "control.sock"
    socket_path.write_text("foreign path", encoding="utf-8")
    config = _config(tmp_path, name="missing-parent/data", socket_name="control.sock")

    async def _unexpected_service_build(
        _cls: type[DaemonServices],
        _config: DaemonConfig,
        *,
        authority_claim: DaemonAuthorityClaim,
    ) -> DaemonServices:
        del authority_claim
        raise AssertionError("service construction reached unsafe control path")

    monkeypatch.setattr(
        DaemonServices,
        "_build_claimed",
        classmethod(_unexpected_service_build),
    )
    services: DaemonServices | None = None
    try:
        with pytest.raises(OSError, match="not a socket"):
            services = await DaemonServices.build(config)
    finally:
        if services is not None:
            await services.shutdown()
    assert socket_path.read_text(encoding="utf-8") == "foreign path"
    assert not config.data_dir.parent.exists()


@pytest.mark.asyncio
async def test_f3_active_foreign_socket_fails_before_data_initialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    config = _config(tmp_path, name="missing-parent/data", socket_name="control.sock")
    foreign = ControlServer(config.socket_path)
    await foreign.start()
    foreign_identity = config.socket_path.stat().st_dev, config.socket_path.stat().st_ino

    async def _unexpected_service_build(
        _cls: type[DaemonServices],
        _config: DaemonConfig,
        *,
        authority_claim: DaemonAuthorityClaim,
    ) -> DaemonServices:
        del authority_claim
        raise AssertionError("service construction reached active control socket")

    monkeypatch.setattr(
        DaemonServices,
        "_build_claimed",
        classmethod(_unexpected_service_build),
    )
    services: DaemonServices | None = None
    try:
        with pytest.raises(OSError, match="already active"):
            services = await DaemonServices.build(config)
        assert (config.socket_path.stat().st_dev, config.socket_path.stat().st_ino) == (
            foreign_identity
        )
        assert not config.data_dir.parent.exists()
    finally:
        if services is not None:
            await services.shutdown()
        await foreign.stop()


@pytest.mark.asyncio
async def test_f3_mismatched_injected_claim_cannot_remove_config_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    claimed_config = _config(tmp_path, name="claimed", socket_name="claimed.sock")
    supplied_config = _config(tmp_path, name="supplied", socket_name="supplied.sock")
    claim = acquire_daemon_authority_claim(claimed_config)
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(supplied_config.socket_path))
    stale.close()
    before = supplied_config.socket_path.lstat()

    with pytest.raises(
        AuthorityClaimError,
        match="daemon authority claim does not cover this configuration",
    ):
        await DaemonServices.build(supplied_config, authority_claim=claim)

    after = supplied_config.socket_path.lstat()
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    assert stat.S_ISSOCK(after.st_mode)
    assert claim.released
