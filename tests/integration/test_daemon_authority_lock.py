"""F3 daemon mutable-authority admission regressions."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import queue
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.authority import (
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
    proceed.set()

    with pytest.raises(asyncio.CancelledError):
        await build_task

    successor_claim = acquire_daemon_authority_claim(config)
    successor_claim.release()
