"""F3 daemon mutable-authority admission regressions."""

from __future__ import annotations

import asyncio
import json
import multiprocessing
import os
import queue
import signal
import socket
import stat
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

import shisad.core.authority as authority
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
from shisad.interop.a2a_registry import A2aConfig, A2aIdentityConfig
from shisad.security.control_plane.sidecar import start_control_plane_sidecar
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


def _hold_claimed_sidecar_after_parent_ready(
    data_dir: str,
    socket_path: str,
    policy_path: str,
    outcome: Any,
) -> None:
    async def _run() -> None:
        config = DaemonConfig(
            data_dir=Path(data_dir),
            socket_path=Path(socket_path),
            policy_path=Path(policy_path),
        )
        claim = acquire_daemon_authority_claim(config)
        initialize_claimed_daemon_authorities(config, claim)
        try:
            handle = await start_control_plane_sidecar(
                data_dir=config.data_dir,
                policy_path=config.policy_path,
                authority_claim=claim,
            )
        except BaseException as exc:
            outcome.put(("error", type(exc).__name__, str(exc)))
            claim.release()
            return
        outcome.put(("ready", handle.process.pid))
        await asyncio.Event().wait()

    asyncio.run(_run())


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


def test_f3_alias_contained_authorities_use_canonical_data_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH", raising=False)
    canonical_root = tmp_path / "canonical-data"
    canonical_root.mkdir(mode=0o700)
    alias = tmp_path / "data-alias"
    alias.symlink_to(canonical_root, target_is_directory=True)
    config = DaemonConfig(
        data_dir=alias,
        socket_path=alias / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )

    candidates = {item.role: item for item in derive_daemon_authority_candidates(config)}

    assert candidates["data_root"].path == canonical_root
    assert candidates["control_socket"].path == canonical_root / "control.sock"
    assert candidates["approval_factor_store"].path == canonical_root / "approval-factors.json"


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
    data_dir.parent.chmod(0o700)
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


@pytest.mark.asyncio
async def test_f3_daemon_build_rejects_writable_data_root_before_legacy_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    config = _config(tmp_path, name="writable-root", socket_name="writable.sock")
    config.data_dir.mkdir(parents=True)
    config.data_dir.parent.chmod(0o700)
    config.data_dir.chmod(0o775)
    outside = tmp_path / "attacker-controlled"
    outside.mkdir()
    sentinel = outside / "legacy-key"
    sentinel.write_bytes(b"attacker-controlled")
    legacy = config.data_dir / "memory"
    legacy.symlink_to(outside, target_is_directory=True)
    reached_claimed_builder = False

    async def _unexpected_build(
        _cls: type[DaemonServices],
        _config: DaemonConfig,
        *,
        authority_claim: DaemonAuthorityClaim,
    ) -> DaemonServices:
        nonlocal reached_claimed_builder
        del authority_claim
        reached_claimed_builder = True
        raise AssertionError("claimed builder reached with writable data root")

    monkeypatch.setattr(DaemonServices, "_build_claimed", classmethod(_unexpected_build))

    with pytest.raises(AuthorityClaimError, match="writable by another uid"):
        await DaemonServices.build(config)

    assert reached_claimed_builder is False
    assert stat.S_IMODE(config.data_dir.stat().st_mode) == 0o775
    assert legacy.is_symlink()
    assert sentinel.read_bytes() == b"attacker-controlled"
    successor_claim = acquire_daemon_authority_claim(config)
    successor_claim.release()


@pytest.mark.asyncio
@pytest.mark.parametrize("root_exists", [True, False])
async def test_f3_daemon_build_rejects_writable_nonsticky_data_root_ancestry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    root_exists: bool,
) -> None:
    clear_remote_provider_env(monkeypatch)
    config = _config(tmp_path, name="writable-parent", socket_name="ancestry.sock")
    config.data_dir.parent.mkdir(parents=True)
    config.data_dir.parent.chmod(0o777)
    outside = tmp_path / "attacker-controlled-ancestry"
    outside.mkdir()
    sentinel = outside / "legacy-key"
    sentinel.write_bytes(b"attacker-controlled")
    legacy = config.data_dir / "memory"
    if root_exists:
        config.data_dir.mkdir(mode=0o700)
        legacy.symlink_to(outside, target_is_directory=True)
    reached_claimed_builder = False

    async def _unexpected_build(
        _cls: type[DaemonServices],
        _config: DaemonConfig,
        *,
        authority_claim: DaemonAuthorityClaim,
    ) -> DaemonServices:
        nonlocal reached_claimed_builder
        del authority_claim
        reached_claimed_builder = True
        raise AssertionError("claimed builder reached below writable ancestry")

    monkeypatch.setattr(DaemonServices, "_build_claimed", classmethod(_unexpected_build))

    with pytest.raises(AuthorityClaimError, match="writable by another uid"):
        await DaemonServices.build(config)

    assert reached_claimed_builder is False
    assert stat.S_IMODE(config.data_dir.parent.stat().st_mode) == 0o777
    assert config.data_dir.exists() is root_exists
    if root_exists:
        assert stat.S_IMODE(config.data_dir.stat().st_mode) == 0o700
        assert legacy.is_symlink()
    assert sentinel.read_bytes() == b"attacker-controlled"
    successor_claim = acquire_daemon_authority_claim(config)
    successor_claim.release()


def test_f3_data_root_rejects_filesystem_root() -> None:
    with pytest.raises(AuthorityClaimError, match="cannot be the filesystem root"):
        authority._ensure_owner_directory(Path("/"))


@pytest.mark.asyncio
async def test_f3_daemon_build_binds_runtime_to_admitted_canonical_data_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.daemon import services as services_module

    clear_remote_provider_env(monkeypatch)
    safe_root = tmp_path / "claimed-root"
    safe_root.mkdir(mode=0o700)
    attacker_root = tmp_path / "retargeted-root"
    attacker_root.mkdir(mode=0o700)
    alias = tmp_path / "data-alias"
    alias.symlink_to(safe_root, target_is_directory=True)
    config = _config(tmp_path, name="unused", socket_name="retarget.sock").model_copy(
        update={"data_dir": alias, "socket_path": alias / "control.sock"}
    )
    real_initialize = initialize_claimed_daemon_authorities
    built_config: DaemonConfig | None = None
    built_claim: DaemonAuthorityClaim | None = None

    def _initialize_then_retarget(
        run_config: DaemonConfig,
        claim: DaemonAuthorityClaim,
    ) -> None:
        real_initialize(run_config, claim)
        alias.unlink()
        alias.symlink_to(attacker_root, target_is_directory=True)

    async def _capture_build(
        _cls: type[DaemonServices],
        run_config: DaemonConfig,
        *,
        authority_claim: DaemonAuthorityClaim,
    ) -> DaemonServices:
        nonlocal built_config, built_claim
        built_config = run_config
        built_claim = authority_claim
        server = ControlServer(run_config.socket_path)
        await server.start()
        await server.stop()
        (run_config.data_dir / "runtime-marker").write_bytes(b"claimed")
        return object.__new__(DaemonServices)

    monkeypatch.setattr(
        services_module,
        "initialize_claimed_daemon_authorities",
        _initialize_then_retarget,
    )
    monkeypatch.setattr(DaemonServices, "_build_claimed", classmethod(_capture_build))

    await DaemonServices.build(config)
    try:
        assert alias.resolve() == attacker_root
        assert built_config is not None
        assert built_config.data_dir == safe_root
        assert built_config.socket_path == safe_root / "control.sock"
        assert (safe_root / "runtime-marker").read_bytes() == b"claimed"
        assert not (attacker_root / "runtime-marker").exists()
        assert built_claim is not None
        approval_candidate = next(
            candidate
            for candidate in built_claim.candidates
            if candidate.role == "approval_factor_store"
        )
        assert approval_candidate.path == safe_root / "approval-factors.json"
    finally:
        if built_claim is not None:
            built_claim.release()


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


def test_f3_fresh_config_union_claim_narrows_without_admission_gap(
    tmp_path: Path,
) -> None:
    prior = _config(tmp_path, name="prior", socket_name="prior.sock")
    refreshed = _config(tmp_path, name="refreshed", socket_name="refreshed.sock")

    claim = authority.acquire_fresh_config_authority_claim(
        prior,
        refreshed,
        timeout_seconds=0,
    )
    prior_successor: DaemonAuthorityClaim | None = None
    try:
        assert not prior.data_dir.exists()
        assert not refreshed.data_dir.exists()
        claimed_paths = {candidate.path for candidate in claim.candidates}
        assert prior.data_dir.resolve(strict=False) in claimed_paths
        assert (prior.data_dir / "config-backups").resolve(strict=False) in claimed_paths
        with pytest.raises(AuthorityConflictError):
            acquire_daemon_authority_claim(prior)
        with pytest.raises(AuthorityConflictError):
            acquire_daemon_authority_claim(refreshed)

        authority.narrow_daemon_authority_claim(refreshed, claim)

        assert tuple((item.role, item.path) for item in claim.candidates) == tuple(
            (item.role, item.path) for item in derive_daemon_authority_candidates(refreshed)
        )
        prior_successor = acquire_daemon_authority_claim(prior)
        with pytest.raises(AuthorityConflictError):
            acquire_daemon_authority_claim(refreshed)
    finally:
        if prior_successor is not None:
            prior_successor.release()
        claim.release()


def test_f3_claim_duplicates_verifiable_sidecar_lease(tmp_path: Path) -> None:
    config = _config(tmp_path, name="lease", socket_name="lease.sock")
    claim = acquire_daemon_authority_claim(config)
    lease = claim.duplicate_lease()
    try:
        candidates = authority.verify_inherited_daemon_authority_lease(
            lease,
            data_dir=config.data_dir,
        )
        assert any(
            candidate.role == "data_root"
            and candidate.path == config.data_dir.resolve(strict=False)
            for candidate in candidates
        )
        with pytest.raises(AuthorityClaimError, match="data root"):
            authority.verify_inherited_daemon_authority_lease(
                lease,
                data_dir=tmp_path / "another-data-root",
            )
        wrong_path_lease = authority.DaemonAuthorityLease(
            fd=os.dup(lease.fd),
            record_path=tmp_path / "not-the-claim.json",
        )
        try:
            with pytest.raises(AuthorityClaimError, match="record path"):
                authority.verify_inherited_daemon_authority_lease(
                    wrong_path_lease,
                    data_dir=config.data_dir,
                )
        finally:
            wrong_path_lease.close()
        wrong_fd = os.open(lease.record_path, os.O_RDWR)
        wrong_descriptor_lease = authority.DaemonAuthorityLease(
            fd=wrong_fd,
            record_path=lease.record_path,
            namespace_fd=os.dup(lease.namespace_fd),
        )
        try:
            with pytest.raises(AuthorityClaimError, match="lock is not held"):
                authority.verify_inherited_daemon_authority_lease(
                    wrong_descriptor_lease,
                    data_dir=config.data_dir,
                )
        finally:
            wrong_descriptor_lease.close()
    finally:
        lease.close()
        claim.release()


def test_f3_inherited_lease_requires_exact_data_root_candidate(tmp_path: Path) -> None:
    config = _config(tmp_path, name="lease-missing-root", socket_name="missing-root.sock")
    claim = acquire_daemon_authority_claim(config)
    control_socket = tuple(
        candidate for candidate in claim.candidates if candidate.role == "control_socket"
    )
    claim.narrow_to(control_socket)
    lease = claim.duplicate_lease()
    try:
        with pytest.raises(AuthorityClaimError, match="data root"):
            authority.verify_inherited_daemon_authority_lease(
                lease,
                data_dir=config.data_dir,
            )
    finally:
        lease.close()
        claim.release()


def test_f3_inherited_lease_keeps_record_visible_after_parent_reference_release(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, name="lease-reference", socket_name="lease-reference.sock")
    claim = acquire_daemon_authority_claim(config)
    lease = claim.duplicate_lease()
    successor: DaemonAuthorityClaim | None = None
    try:
        claim.release()
        assert lease.record_path.exists()
        with pytest.raises(AuthorityConflictError):
            acquire_daemon_authority_claim(config)

        lease.close()
        successor = acquire_daemon_authority_claim(config)
    finally:
        lease.close()
        claim.release()
        if successor is not None:
            successor.release()


def test_f3_fresh_config_union_waits_without_holding_registry_guard(
    tmp_path: Path,
) -> None:
    prior = _config(tmp_path, name="prior", socket_name="prior.sock")
    refreshed = _config(tmp_path, name="refreshed", socket_name="refreshed.sock")
    active = acquire_daemon_authority_claim(prior)
    released = threading.Event()

    def _release_prior() -> None:
        time.sleep(0.05)
        active.release()
        released.set()

    thread = threading.Thread(target=_release_prior)
    thread.start()
    claim: DaemonAuthorityClaim | None = None
    try:
        claim = authority.acquire_fresh_config_authority_claim(
            prior,
            refreshed,
            timeout_seconds=1,
            retry_interval_seconds=0.01,
        )
        assert released.is_set()
        assert not prior.data_dir.exists()
        assert not refreshed.data_dir.exists()
    finally:
        if claim is not None:
            claim.release()
        if not active.released:
            active.release()
        thread.join(timeout=1)


def test_f3_fresh_config_union_timeout_mutates_neither_tree(
    tmp_path: Path,
) -> None:
    prior = _config(tmp_path, name="prior", socket_name="prior.sock")
    refreshed = _config(tmp_path, name="refreshed", socket_name="refreshed.sock")
    active = acquire_daemon_authority_claim(prior)
    try:
        with pytest.raises(AuthorityConflictError, match="timed out"):
            authority.acquire_fresh_config_authority_claim(
                prior,
                refreshed,
                timeout_seconds=0,
            )
        assert not prior.data_dir.exists()
        assert not refreshed.data_dir.exists()
        assert not (prior.data_dir / "config-backups").exists()
    finally:
        active.release()


def test_f3_fresh_config_union_rejects_preexisting_backup_symlink(
    tmp_path: Path,
) -> None:
    prior = _config(tmp_path, name="prior", socket_name="prior.sock")
    refreshed = _config(tmp_path, name="refreshed", socket_name="refreshed.sock")
    prior.data_dir.mkdir(parents=True)
    prior.data_dir.chmod(0o700)
    outside = tmp_path / "outside-backups"
    outside.mkdir()
    (prior.data_dir / "config-backups").symlink_to(outside, target_is_directory=True)

    claim: DaemonAuthorityClaim | None = None
    try:
        with pytest.raises(AuthorityRegistryError, match=r"config_backup_root.*symlink"):
            claim = authority.acquire_fresh_config_authority_claim(
                prior,
                refreshed,
                timeout_seconds=0,
            )
    finally:
        if claim is not None:
            claim.release()

    assert list(outside.iterdir()) == []


def test_f3_fresh_config_same_root_deduplicates_then_narrows(
    tmp_path: Path,
) -> None:
    prior = _config(tmp_path, name="shared", socket_name="prior.sock")
    refreshed = _config(tmp_path, name="shared", socket_name="refreshed.sock")
    claim = authority.acquire_fresh_config_authority_claim(
        prior,
        refreshed,
        timeout_seconds=0,
    )
    try:
        data_candidates = [item for item in claim.candidates if item.role == "data_root"]
        assert len(data_candidates) == 1
        assert any(item.role == "config_backup_root" for item in claim.candidates)

        authority.narrow_daemon_authority_claim(refreshed, claim)

        assert not any(item.role == "config_backup_root" for item in claim.candidates)
        assert len([item for item in claim.candidates if item.role == "data_root"]) == 1
    finally:
        claim.release()


@pytest.mark.parametrize("prior_is_outer", [True, False])
def test_f3_fresh_config_nested_roots_narrow_to_refreshed_tree(
    tmp_path: Path,
    prior_is_outer: bool,
) -> None:
    outer = _config(tmp_path, name="outer", socket_name="outer.sock")
    inner = _config(tmp_path, name="inner", socket_name="inner.sock").model_copy(
        update={"data_dir": outer.data_dir / "nested"}
    )
    prior, refreshed = (outer, inner) if prior_is_outer else (inner, outer)
    claim = authority.acquire_fresh_config_authority_claim(
        prior,
        refreshed,
        timeout_seconds=0,
    )
    try:
        authority.narrow_daemon_authority_claim(refreshed, claim)
        assert {item.path for item in claim.candidates if item.role == "data_root"} == {
            refreshed.data_dir.resolve(strict=False)
        }
        assert not outer.data_dir.exists()
    finally:
        claim.release()


def test_f3_reversed_fresh_config_union_admission_has_one_winner(
    tmp_path: Path,
) -> None:
    prior = _config(tmp_path, name="prior", socket_name="prior.sock")
    refreshed = _config(tmp_path, name="refreshed", socket_name="refreshed.sock")
    barrier = threading.Barrier(2)
    allow_release = threading.Event()
    outcomes: queue.Queue[tuple[str, object]] = queue.Queue()

    def _contend(
        contender_prior: DaemonConfig,
        contender_refreshed: DaemonConfig,
    ) -> None:
        barrier.wait(timeout=3)
        try:
            claim = authority.acquire_fresh_config_authority_claim(
                contender_prior,
                contender_refreshed,
                timeout_seconds=0,
            )
        except AuthorityConflictError as exc:
            outcomes.put(("conflict", exc))
            return
        outcomes.put(("claimed", claim))
        allow_release.wait(timeout=3)
        claim.release()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_contend, prior, refreshed),
            pool.submit(_contend, refreshed, prior),
        ]
        first = outcomes.get(timeout=3)
        second = outcomes.get(timeout=3)
        assert sorted((first[0], second[0])) == ["claimed", "conflict"]
        assert not prior.data_dir.exists()
        assert not refreshed.data_dir.exists()
        assert not (prior.data_dir / "config-backups").exists()
        assert not (refreshed.data_dir / "config-backups").exists()
        allow_release.set()
        for future in futures:
            future.result(timeout=3)


def test_f3_disjoint_fresh_config_unions_can_coexist(tmp_path: Path) -> None:
    prior_a = _config(tmp_path, name="prior-a", socket_name="prior-a.sock")
    refreshed_a = _config(tmp_path, name="refreshed-a", socket_name="refreshed-a.sock")
    prior_b = _config(tmp_path, name="prior-b", socket_name="prior-b.sock")
    refreshed_b = _config(tmp_path, name="refreshed-b", socket_name="refreshed-b.sock")

    claim_a = authority.acquire_fresh_config_authority_claim(
        prior_a,
        refreshed_a,
        timeout_seconds=0,
    )
    try:
        claim_b = authority.acquire_fresh_config_authority_claim(
            prior_b,
            refreshed_b,
            timeout_seconds=0,
        )
        claim_b.release()
    finally:
        claim_a.release()

    assert not prior_a.data_dir.exists()
    assert not refreshed_a.data_dir.exists()
    assert not prior_b.data_dir.exists()
    assert not refreshed_b.data_dir.exists()


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
@pytest.mark.parametrize(
    ("surface", "expected_role"),
    [
        ("socket", "control_socket"),
        ("approval", "approval_factor_store"),
        ("soul", "soul"),
    ],
)
async def test_f3_live_daemon_rejects_shared_external_authority_without_disturbing_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    expected_role: str,
) -> None:
    clear_remote_provider_env(monkeypatch)
    monkeypatch.delenv("SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH", raising=False)
    winner_config = _config(tmp_path, name="winner", socket_name="winner.sock")
    loser_config = _config(tmp_path, name="loser", socket_name="loser.sock")
    if surface == "socket":
        loser_config = loser_config.model_copy(update={"socket_path": winner_config.socket_path})
    elif surface == "approval":
        monkeypatch.setenv(
            "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
            str(tmp_path / "shared-approval.json"),
        )
    else:
        shared_soul = tmp_path / "shared-soul" / "SOUL.md"
        winner_config = winner_config.model_copy(
            update={"assistant_persona_soul_path": shared_soul}
        )
        loser_config = loser_config.model_copy(update={"assistant_persona_soul_path": shared_soul})

    winner_task = asyncio.create_task(run_daemon(winner_config))
    client = ControlClient(winner_config.socket_path)
    try:
        await _wait_for_socket(winner_config.socket_path)
        winner_socket = winner_config.socket_path.lstat()
        await client.connect()

        with pytest.raises(AuthorityConflictError, match=expected_role):
            await run_daemon(loser_config)

        current_socket = winner_config.socket_path.lstat()
        assert (current_socket.st_dev, current_socket.st_ino) == (
            winner_socket.st_dev,
            winner_socket.st_ino,
        )
        if loser_config.socket_path != winner_config.socket_path:
            assert not loser_config.socket_path.exists()
        assert not loser_config.data_dir.exists()
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


@pytest.mark.parametrize("surface", ["policy", "signers", "a2a_private"])
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
    private_key_path = tmp_path / "a2a-private.key"
    if surface == "policy":
        policy_path = tmp_path / "data" / "policy.yaml"
    elif surface == "signers":
        signers_path = tmp_path / "approval.corrupt.allowed_signers"
    else:
        private_key_path = tmp_path / "data" / "a2a-private.key"
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        selfmod_allowed_signers_path=signers_path,
        a2a=A2aConfig(
            enabled=True,
            identity=A2aIdentityConfig(
                agent_id="local-agent",
                private_key_path=private_key_path,
                public_key_path=tmp_path / "a2a-public.key",
            ),
        ),
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


def test_f3_active_claim_refresh_rejects_replaced_hardlink_alias(
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
        with pytest.raises(AuthorityRegistryError, match="hardlinked"):
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


@pytest.mark.parametrize("operation", ["acquire", "narrow"])
@pytest.mark.parametrize("replacement", ["registry", "claim"])
def test_f3_authority_namespace_replacement_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    replacement: str,
) -> None:
    registry_root = tmp_path / "authority-registry"
    monkeypatch.setattr(authority, "_registry_root", lambda: registry_root)
    first = _config(tmp_path, name="first", socket_name="first.sock")
    claim = acquire_daemon_authority_claim(first)
    detached = tmp_path / f"detached-{replacement}"
    replacement_path: Path
    try:
        if replacement == "registry":
            registry_root.rename(detached)
            registry_root.mkdir(mode=0o700)
            replacement_path = registry_root
        else:
            record_path = claim._record_path
            record_path.rename(detached)
            record_path.write_bytes(detached.read_bytes())
            record_path.chmod(0o600)
            replacement_path = record_path

        if operation == "acquire":
            second = _config(tmp_path, name="second", socket_name="second.sock")
            with pytest.raises(AuthorityRegistryError, match="namespace"):
                acquire_daemon_authority_claim(second)
        else:
            with pytest.raises((AuthorityRegistryError, AuthorityClaimError), match="namespace"):
                claim.narrow_to(claim.candidates)

        if replacement == "registry":
            assert replacement_path.is_dir()
            replacement_path.rmdir()
            detached.rename(registry_root)
        else:
            replacement_path.unlink()
            detached.rename(replacement_path)
    finally:
        with suppress(AuthorityRegistryError):
            claim.release()
        if detached.exists() and not registry_root.exists():
            detached.rename(registry_root)


def test_f3_recursive_authority_claim_json_fails_through_typed_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_root = tmp_path / "authority-registry"
    monkeypatch.setattr(authority, "_registry_root", lambda: registry_root)
    first = _config(tmp_path, name="first", socket_name="first.sock")
    claim = acquire_daemon_authority_claim(first)
    try:
        recursive_bytes = b"[" * 10_000 + b"]" * 10_000
        claim._record_path.write_bytes(recursive_bytes)
        claim._record_path.chmod(0o600)
        second = _config(tmp_path, name="second", socket_name="second.sock")

        with pytest.raises(AuthorityRegistryError, match="claim record is corrupt"):
            acquire_daemon_authority_claim(second)
    finally:
        claim.release()


def test_f3_oversized_integer_claim_json_fails_through_typed_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_root = tmp_path / "authority-registry"
    monkeypatch.setattr(authority, "_registry_root", lambda: registry_root)
    first = _config(tmp_path, name="first", socket_name="first.sock")
    claim = acquire_daemon_authority_claim(first)
    try:
        ambiguous_bytes = b'{"version":2,"candidates":[],"unchecked":' + b"9" * 5000 + b"}"
        claim._record_path.write_bytes(ambiguous_bytes)
        claim._record_path.chmod(0o600)
        second = _config(tmp_path, name="second", socket_name="second.sock")

        with pytest.raises(AuthorityRegistryError, match="claim record is corrupt"):
            acquire_daemon_authority_claim(second)
    finally:
        claim.release()


@pytest.mark.parametrize(
    "mutation",
    [
        "record_extra",
        "candidate_extra",
        "invalid_pid_type",
        "negative_pid",
        "invalid_device_type",
        "negative_device",
        "invalid_inode_type",
        "negative_inode",
    ],
)
def test_f3_authority_claim_rejects_unknown_members_and_invalid_identity_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    registry_root = tmp_path / "authority-registry"
    monkeypatch.setattr(authority, "_registry_root", lambda: registry_root)
    first = _config(tmp_path, name="first", socket_name="first.sock")
    claim = acquire_daemon_authority_claim(first)
    original = claim._record_path.read_bytes()
    try:
        payload = json.loads(original)
        if mutation == "record_extra":
            payload["unexpected_authority"] = "ignored"
        elif mutation == "candidate_extra":
            payload["candidates"][0]["unexpected_authority"] = "ignored"
        elif mutation == "invalid_pid_type":
            payload["pid"] = "123"
        elif mutation == "negative_pid":
            payload["pid"] = -1
        elif mutation == "invalid_device_type":
            payload["candidates"][0]["device"] = "123"
        elif mutation == "negative_device":
            payload["candidates"][0]["device"] = -1
        elif mutation == "invalid_inode_type":
            payload["candidates"][0]["inode"] = "123"
        else:
            payload["candidates"][0]["inode"] = -1
        retained = json.dumps(payload, sort_keys=True).encode()
        claim._record_path.write_bytes(retained)
        claim._record_path.chmod(0o600)
        with pytest.raises(AuthorityRegistryError, match="claim"):
            authority._read_claim_record(claim._fd, claim._record_path)

        assert claim._record_path.read_bytes() == retained
    finally:
        claim._record_path.write_bytes(original)
        claim._record_path.chmod(0o600)
        claim.release()


def test_f3_registry_replacement_during_acquisition_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_root = tmp_path / "authority-registry"
    detached = tmp_path / "detached-registry"
    monkeypatch.setattr(authority, "_registry_root", lambda: registry_root)
    real_publish = authority._publish_claim

    def _replace_then_publish(root: Path, candidates):
        root.rename(detached)
        root.mkdir(mode=0o700)
        return real_publish(root, candidates)

    monkeypatch.setattr(authority, "_publish_claim", _replace_then_publish)
    with pytest.raises(AuthorityRegistryError, match="namespace identity changed"):
        acquire_daemon_authority_claim(_config(tmp_path, name="raced", socket_name="raced.sock"))

    for path in registry_root.iterdir():
        path.unlink()
    registry_root.rmdir()
    detached.rename(registry_root)


def test_f3_claim_replacement_during_narrowing_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_root = tmp_path / "authority-registry"
    monkeypatch.setattr(authority, "_registry_root", lambda: registry_root)
    claim = acquire_daemon_authority_claim(
        _config(tmp_path, name="raced", socket_name="raced.sock")
    )
    record_path = claim._record_path
    detached = tmp_path / "detached-claim"
    real_write = authority._write_claim_record

    def _replace_then_write(fd: int, candidates) -> None:
        record_path.rename(detached)
        record_path.write_bytes(detached.read_bytes())
        record_path.chmod(0o600)
        real_write(fd, candidates)

    monkeypatch.setattr(authority, "_write_claim_record", _replace_then_write)
    try:
        with pytest.raises(AuthorityRegistryError, match="namespace identity changed"):
            claim.narrow_to(claim.candidates)
        record_path.unlink()
        detached.rename(record_path)
    finally:
        claim.release()


@pytest.mark.parametrize(
    "surface",
    ["data", "socket", "policy", "approval", "soul", "signers", "a2a_private"],
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
    private_key_path = control / "a2a-private.key"
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
    elif surface == "signers":
        signers_path = workspace / "allowed_signers"
    else:
        private_key_path = workspace / "a2a-private.key"
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
        a2a=A2aConfig(
            enabled=True,
            identity=A2aIdentityConfig(
                agent_id="local-agent",
                private_key_path=private_key_path,
                public_key_path=control / "a2a-public.key",
            ),
        ),
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


@pytest.mark.parametrize("role", ["approval", "soul"])
@pytest.mark.parametrize("artifact_kind", ["base", "derived"])
def test_f3_hardlinked_external_authority_fails_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    artifact_kind: str,
) -> None:
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("unrelated", encoding="utf-8")
    unrelated.chmod(0o644)
    configured = tmp_path / ("approval.json" if role == "approval" else "SOUL.md")
    artifact = (
        configured
        if artifact_kind == "base"
        else configured.with_name(f"{configured.name}.corrupt.retained")
    )
    artifact.hardlink_to(unrelated)
    if artifact_kind == "derived":
        configured.write_text("configured", encoding="utf-8")
        configured.chmod(0o600)
    if role == "approval":
        monkeypatch.setenv(
            "SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH",
            str(configured),
        )
        config = _config(tmp_path, name="data", socket_name="control.sock")
    else:
        config = DaemonConfig(
            data_dir=tmp_path / "data",
            socket_path=tmp_path / "control.sock",
            policy_path=tmp_path / "policy.yaml",
            assistant_persona_soul_path=configured,
        )
    before = unrelated.stat()
    claim: DaemonAuthorityClaim | None = None
    try:
        with pytest.raises(AuthorityRegistryError, match="hardlink"):
            claim = acquire_daemon_authority_claim(config)
    finally:
        if claim is not None:
            claim.release()
    after = unrelated.stat()
    assert (after.st_ino, after.st_mode, after.st_mtime_ns, unrelated.read_bytes()) == (
        before.st_ino,
        before.st_mode,
        before.st_mtime_ns,
        b"unrelated",
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


@pytest.mark.parametrize("role", ["approval", "soul"])
def test_f3_missing_external_authority_rejects_unsafe_parent_before_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    unsafe_parent = tmp_path / "unsafe-parent"
    unsafe_parent.mkdir(mode=0o777)
    unsafe_parent.chmod(0o777)
    approval_path = (
        unsafe_parent / "approval.json" if role == "approval" else tmp_path / "approval.json"
    )
    soul_path = unsafe_parent / "SOUL.md" if role == "soul" else None
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

    with pytest.raises(AuthorityRegistryError, match="unsafe parent ancestry"):
        acquire_daemon_authority_claim(config)

    assert list(unsafe_parent.iterdir()) == []
    assert not config.data_dir.exists()


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


@pytest.mark.asyncio
async def test_f3_run_daemon_consumes_transferred_authority_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    with tempfile.TemporaryDirectory(prefix="s3-", dir="/tmp") as raw_root:
        root = Path(raw_root)
        config = _config(root, name="d", socket_name="c.sock")
        claim = acquire_daemon_authority_claim(config)
        daemon_task = asyncio.create_task(run_daemon(config, authority_claim=claim))
        client = ControlClient(config.socket_path)
        try:
            await _wait_for_socket(config.socket_path)
            await client.connect()
            status = await client.call("daemon.status")
            assert status["status"] == "running"
        finally:
            with suppress(Exception):
                await client.call("daemon.shutdown")
            await client.close()
            await asyncio.wait_for(daemon_task, timeout=3)
        assert claim.released


@pytest.mark.asyncio
async def test_f3_orphan_sidecar_retains_claim_until_listener_and_writers_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    config = _config(tmp_path, name="orphan", socket_name="orphan.sock")
    context = multiprocessing.get_context("spawn")
    outcome = context.Queue()
    parent = context.Process(
        target=_hold_claimed_sidecar_after_parent_ready,
        args=(
            os.fspath(config.data_dir),
            os.fspath(config.socket_path),
            os.fspath(config.policy_path),
            outcome,
        ),
    )
    sidecar_pid: int | None = None
    successor_claim: DaemonAuthorityClaim | None = None
    successor_handle: Any = None
    parent.start()
    try:
        ready = outcome.get(timeout=20)
        assert ready[0] == "ready", ready
        sidecar_pid = int(ready[1])
        os.kill(sidecar_pid, signal.SIGSTOP)
        parent.kill()
        parent.join(timeout=5)
        assert parent.exitcode is not None

        root_stat = config.data_dir.stat()
        children = sorted(path.name for path in config.data_dir.iterdir())
        with pytest.raises(AuthorityConflictError):
            acquire_daemon_authority_claim(config)
        after_conflict = config.data_dir.stat()
        assert (after_conflict.st_ino, after_conflict.st_mode, after_conflict.st_mtime_ns) == (
            root_stat.st_ino,
            root_stat.st_mode,
            root_stat.st_mtime_ns,
        )
        assert sorted(path.name for path in config.data_dir.iterdir()) == children

        os.kill(sidecar_pid, signal.SIGCONT)
        deadline = asyncio.get_running_loop().time() + 10
        while True:
            try:
                successor_claim = acquire_daemon_authority_claim(config)
                break
            except AuthorityConflictError:
                if asyncio.get_running_loop().time() >= deadline:
                    raise
                await asyncio.sleep(0.05)

        successor_handle = await start_control_plane_sidecar(
            data_dir=config.data_dir,
            policy_path=config.policy_path,
            authority_claim=successor_claim,
        )
        successor_identity = successor_handle.socket_path.stat()
        await asyncio.sleep(1.1)
        current_identity = successor_handle.socket_path.stat()
        assert (current_identity.st_dev, current_identity.st_ino) == (
            successor_identity.st_dev,
            successor_identity.st_ino,
        )
        assert await successor_handle.client.ping() is True
    finally:
        if parent.is_alive():
            parent.kill()
            parent.join(timeout=5)
        if sidecar_pid is not None:
            with suppress(ProcessLookupError):
                os.kill(sidecar_pid, signal.SIGCONT)
            with suppress(ProcessLookupError):
                os.kill(sidecar_pid, signal.SIGTERM)
        if successor_handle is not None:
            await successor_handle.close()
        if successor_claim is not None:
            successor_claim.release()
