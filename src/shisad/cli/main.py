"""shisad CLI entry point.

Click-based CLI that connects to the daemon via the control API (Unix socket).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from collections.abc import Callable, Coroutine
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import click
import qrcode  # type: ignore[import-untyped]
import yaml
from click.shell_completion import get_completion_class
from pydantic import BaseModel

from shisad.cli.rpc import rpc_call, rpc_run, run_async
from shisad.core.api.schema import (
    ActionConfirmResult,
    ActionPendingEntry,
    ActionPendingResult,
    ActionRejectResult,
    AdminSelfModApplyResult,
    AdminSelfModProposeResult,
    AdminSelfModRollbackResult,
    ChannelPairingProposalResult,
    ConfirmationMetricsResult,
    DaemonShutdownResult,
    DaemonStatusResult,
    DashboardMarkFalsePositiveResult,
    DashboardQueryResult,
    DevCloseResult,
    DevImplementResult,
    DevRemediateResult,
    DevReviewResult,
    DoctorCheckResult,
    FsListResult,
    FsReadResult,
    FsWriteResult,
    GitDiffResult,
    GitLogResult,
    GitStatusResult,
    LockdownSetResult,
    MemoryListResult,
    MemoryRotateKeyResult,
    MemoryWriteResult,
    NoteDeleteResult,
    NoteExportResult,
    NoteGetResult,
    NoteListResult,
    NoteVerifyResult,
    PolicyExplainResult,
    RealityCheckReadResult,
    RealityCheckSearchResult,
    SessionCreateResult,
    SessionExportResult,
    SessionGrantCapabilitiesResult,
    SessionImportResult,
    SessionListResult,
    SessionMessageResult,
    SessionRestoreResult,
    SessionRollbackResult,
    SessionSetModeResult,
    SessionTerminateResult,
    SignerListResult,
    SignerRegisterResult,
    SignerRevokeResult,
    SkillInstallResult,
    SkillListResult,
    SkillReviewResult,
    SkillRevokeResult,
    TaskListResult,
    TodoDeleteResult,
    TodoExportResult,
    TodoGetResult,
    TodoListResult,
    TodoVerifyResult,
    TwoFactorEntry,
    TwoFactorListResult,
    TwoFactorRegisterBeginResult,
    TwoFactorRegisterConfirmResult,
    TwoFactorRevokeResult,
    WebFetchResult,
    WebSearchResult,
)
from shisad.core.config import DaemonConfig
from shisad.ui.evidence import (
    render_evidence_refs_for_terminal,
    sanitize_terminal_field,
    sanitize_terminal_text,
)


def _get_config() -> DaemonConfig:
    return DaemonConfig()


def _colors_enabled() -> bool:
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return True
    return not bool((ctx.obj or {}).get("no_color", False))


def _echo(message: str, *, fg: str | None = None, bold: bool = False, err: bool = False) -> None:
    if fg and _colors_enabled():
        click.secho(message, fg=fg, bold=bold, err=err)
        return
    click.echo(message, err=err)


def _terminal_supports_unicode_output() -> bool:
    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return False
    stream = click.get_text_stream("stdout")
    encoding = str(getattr(stream, "encoding", "") or sys.stdout.encoding or "").lower()
    return "utf" in encoding


def _render_terminal_qr(url: str) -> str:
    if not url or not _terminal_supports_unicode_output():
        return ""
    try:
        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make(fit=True)
        matrix = qr.get_matrix()
    except Exception:
        return ""
    return "\n".join("".join("██" if cell else "  " for cell in row) for row in matrix)


def _dump_model(model: BaseModel) -> str:
    return json.dumps(model.model_dump(mode="json", exclude_unset=True), indent=2)


def _joined_text_arg(values: tuple[str, ...], *, field_name: str) -> str:
    text = " ".join(part.strip() for part in values if part.strip()).strip()
    if not text:
        raise click.ClickException(f"{field_name} is required.")
    return text


def _dev_task_payload(
    *,
    text_key: str,
    text_value: str,
    agent: str,
    file_refs: tuple[Path, ...],
    fallback_agents: tuple[str, ...],
    capabilities: tuple[str, ...],
    max_turns: int | None,
    max_budget_usd: float | None,
    model: str,
    reasoning_effort: str,
    timeout_sec: float | None,
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        text_key: text_value,
        "file_refs": [str(path) for path in file_refs if str(path).strip()],
    }
    if agent.strip():
        payload["agent"] = agent.strip()
    if fallback_agents:
        payload["fallback_agents"] = [item.strip() for item in fallback_agents if item.strip()]
    if capabilities:
        payload["capabilities"] = [item.strip() for item in capabilities if item.strip()]
    if max_turns is not None:
        payload["max_turns"] = max_turns
    if max_budget_usd is not None:
        payload["max_budget_usd"] = max_budget_usd
    if model.strip():
        payload["model"] = model.strip()
    if reasoning_effort.strip():
        payload["reasoning_effort"] = reasoning_effort.strip()
    if timeout_sec is not None:
        payload["timeout_sec"] = timeout_sec
    if extra:
        payload.update(extra)
    return payload


def _parse_relative_duration(value: str) -> timedelta:
    text = value.strip().lower()
    if len(text) < 2:
        raise click.ClickException("Invalid duration. Use formats like 24h, 7d, or 30m.")
    unit = text[-1]
    amount_raw = text[:-1]
    try:
        amount = int(amount_raw)
    except ValueError as exc:
        raise click.ClickException("Invalid duration. Use formats like 24h, 7d, or 30m.") from exc
    if amount < 0:
        raise click.ClickException("Duration must be non-negative.")
    if unit == "s":
        return timedelta(seconds=amount)
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    if unit == "d":
        return timedelta(days=amount)
    raise click.ClickException("Invalid duration unit. Supported: s, m, h, d.")


@contextmanager
def _progress(label: str) -> Any:
    start = time.monotonic()
    _echo(f"{label}...", fg="cyan")
    try:
        yield
    except (click.ClickException, OSError, RuntimeError, TypeError, ValueError):
        elapsed = time.monotonic() - start
        _echo(f"{label} failed ({elapsed:.2f}s)", fg="red", err=True)
        raise
    else:
        elapsed = time.monotonic() - start
        _echo(f"{label} done ({elapsed:.2f}s)", fg="green")


@click.group()
@click.option("--no-color", is_flag=True, help="Disable colored output.")
@click.version_option()
@click.pass_context
def cli(ctx: click.Context, no_color: bool) -> None:
    """shisad — Security-first AI agent daemon."""
    ctx.ensure_object(dict)
    ctx.obj["no_color"] = no_color


@cli.command("completion")
@click.option("--shell", type=click.Choice(["bash", "zsh", "fish"]), required=True)
def completion(shell: str) -> None:
    """Print shell completion script."""
    completion_class = get_completion_class(shell)
    if completion_class is None:
        raise click.ClickException(f"Unsupported shell: {shell}")
    complete = completion_class(
        cli=cli,
        ctx_args={},
        prog_name="shisad",
        complete_var="_SHISAD_COMPLETE",
    )
    script = complete.source()
    click.echo(script)


@cli.command("tui")
@click.option("--interactive", is_flag=True, help="Run interactive confirmation/audit loop.")
@click.option("--plain", is_flag=True, help="Disable rich rendering.")
def tui(interactive: bool, plain: bool) -> None:
    """Render optional terminal dashboard over control API."""
    from shisad.ui.tui import run_interactive, run_once

    config = _get_config()
    if interactive:
        run_async(run_interactive(config.socket_path))
        return
    rendered = run_async(run_once(config.socket_path, rich_output=not plain))
    click.echo(rendered)


@cli.command("chat")
@click.option("--session", "session_id", default="", help="Attach to existing session ID.")
@click.option("--user", "-u", default="ops", help="User ID for new session.")
@click.option("--workspace", "-w", default="default", help="Workspace ID for new session.")
@click.option(
    "--new",
    "new_session",
    is_flag=True,
    help="Force a fresh session (skip user/workspace binding reuse).",
)
def chat(session_id: str, user: str, workspace: str, new_session: bool) -> None:
    """Interactive chat with the shisad daemon."""
    if new_session and session_id:
        raise click.ClickException("--new cannot be used together with --session.")
    try:
        from shisad.ui.chat import ChatApp
    except ModuleNotFoundError as exc:
        missing = (exc.name or "").split(".", maxsplit=1)[0]
        if missing == "textual":
            raise click.ClickException(
                "textual is required for chat TUI. Install with: uv sync --dev"
            ) from exc
        raise click.ClickException(f"chat TUI import failed: missing module '{exc.name}'") from exc
    except ImportError as exc:
        raise click.ClickException(f"chat TUI import failed: {exc}") from exc

    config = _get_config()
    app = ChatApp(
        socket_path=config.socket_path,
        user_id=user,
        workspace_id=workspace,
        session_id=session_id or None,
        reuse_bound_session=not new_session,
    )
    app.run()


@cli.command("web-ui")
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("artifacts/shisad-dashboard.html"),
    help="Output HTML path for dashboard snapshot.",
)
def web_ui(output: Path) -> None:
    """Generate optional API-first web dashboard snapshot."""
    from shisad.ui.web import write_web_snapshot

    config = _get_config()
    out_path = run_async(write_web_snapshot(socket_path=config.socket_path, output_path=output))
    _echo(f"Wrote dashboard snapshot: {out_path}", fg="green")


# --- Daemon lifecycle ---


def _default_autoreload_roots() -> tuple[Path, ...]:
    package_src = Path(__file__).resolve().parents[1]
    repo_src = Path(__file__).resolve().parents[3] / "src" / "shisad"
    if repo_src.exists():
        return (repo_src,)
    return (package_src,)


def _snapshot_autoreload_files(watch_roots: tuple[Path, ...]) -> dict[Path, int]:
    snapshot: dict[Path, int] = {}
    for root in watch_roots:
        if root.is_file():
            if root.suffix == ".py":
                try:
                    snapshot[root] = root.stat().st_mtime_ns
                except FileNotFoundError:
                    continue
            continue
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if not path.is_file():
                continue
            try:
                snapshot[path] = path.stat().st_mtime_ns
            except FileNotFoundError:
                continue
    return snapshot


async def _wait_for_autoreload_change(
    *,
    watch_roots: tuple[Path, ...],
    baseline: dict[Path, int],
    poll_interval: float,
) -> dict[Path, int]:
    effective_interval = max(0.01, poll_interval)
    while True:
        await asyncio.sleep(effective_interval)
        current = _snapshot_autoreload_files(watch_roots)
        if current != baseline:
            return current


async def _run_daemon_with_autoreload(
    *,
    config: DaemonConfig,
    watch_roots: tuple[Path, ...] | None = None,
    poll_interval: float = 0.5,
    daemon_runner: Callable[[DaemonConfig], Coroutine[Any, Any, None]] | None = None,
) -> None:
    runner = daemon_runner
    if runner is None:
        from shisad.daemon.runner import run_daemon

        runner = run_daemon

    roots = watch_roots or _default_autoreload_roots()
    snapshot = _snapshot_autoreload_files(roots)
    _echo(f"Debug autoreload watching {len(snapshot)} Python files", fg="cyan")

    while True:
        daemon_task: asyncio.Task[None] = asyncio.create_task(runner(config))
        change_task: asyncio.Task[dict[Path, int]] = asyncio.create_task(
            _wait_for_autoreload_change(
                watch_roots=roots,
                baseline=snapshot,
                poll_interval=poll_interval,
            )
        )
        try:
            done, _ = await asyncio.wait(
                {daemon_task, change_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.CancelledError:
            daemon_task.cancel()
            change_task.cancel()
            with suppress(asyncio.CancelledError):
                await daemon_task
            with suppress(asyncio.CancelledError):
                await change_task
            raise

        if daemon_task in done:
            change_task.cancel()
            with suppress(asyncio.CancelledError):
                await change_task
            await daemon_task
            return

        snapshot = change_task.result()
        _echo("Autoreload detected local source changes; restarting daemon", fg="yellow")
        daemon_task.cancel()
        with suppress(asyncio.CancelledError):
            await daemon_task
        if str(config.log_level).strip().upper() == "DEBUG":
            refreshed = _get_config()
            config = refreshed.model_copy(update={"log_level": "DEBUG"})
            _echo("Autoreload reloaded daemon config from environment", fg="cyan")


def _run_daemon_with_autoreload_sync(config: DaemonConfig) -> None:
    run_async(_run_daemon_with_autoreload(config=config))


def _run_daemon_foreground(config: DaemonConfig) -> None:
    from shisad.daemon.runner import run_daemon

    run_async(run_daemon(config))


def _backup_config_snapshot(config: DaemonConfig) -> Path:
    """Write a timestamped JSON snapshot of current config before reload."""
    backup_dir = config.data_dir / "config-backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    backup_path = backup_dir / f"{timestamp}.json"

    # Keep names unique if multiple backups happen within the same second.
    counter = 1
    while backup_path.exists():
        backup_path = backup_dir / f"{timestamp}-{counter}.json"
        counter += 1

    payload = config.model_dump(mode="json")
    backup_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(backup_path, 0o600)
    return backup_path


def _start_daemon(*, config: DaemonConfig, foreground: bool, debug: bool) -> None:
    effective_foreground = foreground or debug
    effective_config = config.model_copy(update={"log_level": "DEBUG"}) if debug else config

    if not effective_foreground:
        _echo(f"Starting shisad daemon (socket: {config.socket_path})", fg="cyan")
        # Full daemonization is a future enhancement; for now, run in foreground
        _echo("Note: --foreground is currently the only supported mode", fg="yellow")
    if debug:
        _echo("Debug mode enabled: foreground + DEBUG logs + autoreload", fg="yellow")

    _echo(f"Data directory: {effective_config.data_dir}")
    _echo(f"Control socket: {effective_config.socket_path}")

    try:
        if debug:
            _run_daemon_with_autoreload_sync(effective_config)
        else:
            _run_daemon_foreground(effective_config)
    except KeyboardInterrupt:
        _echo("\nShutting down...", fg="yellow")


@cli.command()
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (don't daemonize)")
@click.option(
    "--debug",
    is_flag=True,
    help="Run in foreground with DEBUG logging and local autoreload.",
)
def start(foreground: bool, debug: bool) -> None:
    """Start the shisad daemon."""
    _start_daemon(config=_get_config(), foreground=foreground, debug=debug)


@cli.command()
def stop() -> None:
    """Stop the shisad daemon."""
    config = _get_config()

    if not config.socket_path.exists():
        _echo("Daemon does not appear to be running (no socket found)", err=True)
        sys.exit(1)

    with _progress("Connecting"):
        rpc_call(config, "daemon.shutdown", response_model=DaemonShutdownResult)
    _echo("Shutdown signal sent", fg="green")


@cli.command()
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (don't daemonize)")
@click.option(
    "--debug",
    is_flag=True,
    help="Run in foreground with DEBUG logging and local autoreload.",
)
@click.option(
    "--fresh-config",
    is_flag=True,
    help="Reload config from environment after shutdown before start.",
)
def restart(foreground: bool, debug: bool, fresh_config: bool) -> None:
    """Restart the shisad daemon."""
    config = _get_config()

    if config.socket_path.exists():
        with _progress("Connecting"):
            rpc_call(config, "daemon.shutdown", response_model=DaemonShutdownResult)
        _echo("Shutdown signal sent", fg="green")
    else:
        _echo(
            "Daemon does not appear to be running (no socket found); starting anyway",
            fg="yellow",
        )

    if fresh_config:
        backup_path = _backup_config_snapshot(config)
        _echo(f"Saved prior config snapshot: {backup_path}", fg="yellow")
        config = _get_config()
        _echo("Reloaded configuration from environment", fg="cyan")

    _start_daemon(config=config, foreground=foreground, debug=debug)


@cli.command()
def status() -> None:
    """Show daemon status."""
    config = _get_config()

    if not config.socket_path.exists():
        _echo("Status: not running", fg="yellow")
        sys.exit(1)

    try:
        with _progress("Querying daemon status"):
            result = rpc_call(config, "daemon.status", response_model=DaemonStatusResult)
    except click.ClickException as exc:
        _echo(f"Status: error ({exc.message})", err=True)
        sys.exit(1)

    _echo("Status: running", fg="green")
    click.echo(_dump_model(result))


@cli.group()
def doctor() -> None:
    """Runtime diagnostic checks."""


@doctor.command("check")
@click.option(
    "--component",
    default="all",
    help=(
        "Component to check (all, dependencies, provider, policy, channels, sandbox, realitycheck)"
    ),
)
def doctor_check(component: str) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "doctor.check",
        {"component": component},
        response_model=DoctorCheckResult,
    )
    click.echo(_dump_model(result))


@cli.group()
def admin() -> None:
    """Administrative workflows."""


@admin.group("selfmod")
def admin_selfmod() -> None:
    """Signed self-modification artifact controls."""


@admin_selfmod.command("propose")
@click.argument("artifact_path", type=click.Path(exists=True, path_type=Path))
def admin_selfmod_propose(artifact_path: Path) -> None:
    """Inspect and stage a signed artifact proposal."""
    config = _get_config()
    result = rpc_call(
        config,
        "admin.selfmod.propose",
        {"artifact_path": str(artifact_path)},
        response_model=AdminSelfModProposeResult,
    )
    click.echo(
        " ".join(
            [
                f"proposal_id={result.proposal_id}",
                f"artifact_type={result.artifact_type}",
                f"name={result.name}",
                f"version={result.version}",
                f"valid={result.valid}",
            ]
        )
    )


@admin_selfmod.command("apply")
@click.argument("proposal_id")
@click.option("--yes", "confirm", is_flag=True, help="Apply immediately after preview.")
def admin_selfmod_apply(proposal_id: str, confirm: bool) -> None:
    """Preview or apply a staged self-modification proposal."""
    config = _get_config()
    result = rpc_call(
        config,
        "admin.selfmod.apply",
        {"proposal_id": proposal_id, "confirm": confirm},
        response_model=AdminSelfModApplyResult,
    )
    if result.applied:
        click.echo(
            " ".join(
                [
                    "applied=True",
                    f"proposal_id={result.proposal_id}",
                    f"change_id={result.change_id}",
                    f"active_version={result.active_version}",
                ]
            )
        )
        return
    click.echo(_dump_model(result))


@admin_selfmod.command("rollback")
@click.argument("change_id")
def admin_selfmod_rollback(change_id: str) -> None:
    """Rollback a previously applied self-modification change."""
    config = _get_config()
    result = rpc_call(
        config,
        "admin.selfmod.rollback",
        {"change_id": change_id},
        response_model=AdminSelfModRollbackResult,
    )
    click.echo(
        " ".join(
            [
                f"rolled_back={result.rolled_back}",
                f"change_id={result.change_id}",
                f"restored_version={result.restored_version}",
                f"active_version={result.active_version}",
            ]
        )
    )


@cli.group()
def dev() -> None:
    """Developer workflow orchestration helpers."""


@dev.command("implement")
@click.argument("task", nargs=-1, required=True)
@click.option("--agent", default="", help="Preferred coding agent.")
@click.option("--file-ref", "file_refs", multiple=True, type=click.Path(path_type=Path))
@click.option("--fallback-agent", "fallback_agents", multiple=True, help="Fallback coding agent.")
@click.option("--capability", "capabilities", multiple=True, help="Optional TASK capability scope.")
@click.option("--max-turns", type=int, default=None)
@click.option("--max-budget-usd", type=float, default=None)
@click.option("--model", default="")
@click.option("--reasoning-effort", default="")
@click.option("--timeout-sec", type=float, default=None)
def dev_implement(
    task: tuple[str, ...],
    agent: str,
    file_refs: tuple[Path, ...],
    fallback_agents: tuple[str, ...],
    capabilities: tuple[str, ...],
    max_turns: int | None,
    max_budget_usd: float | None,
    model: str,
    reasoning_effort: str,
    timeout_sec: float | None,
) -> None:
    """Dispatch a coding implementation task through the daemon."""
    config = _get_config()
    result = rpc_call(
        config,
        "dev.implement",
        _dev_task_payload(
            text_key="task",
            text_value=_joined_text_arg(task, field_name="task"),
            agent=agent,
            file_refs=file_refs,
            fallback_agents=fallback_agents,
            capabilities=capabilities,
            max_turns=max_turns,
            max_budget_usd=max_budget_usd,
            model=model,
            reasoning_effort=reasoning_effort,
            timeout_sec=timeout_sec,
        ),
        response_model=DevImplementResult,
    )
    click.echo(_dump_model(result))


@dev.command("review")
@click.argument("scope", nargs=-1, required=True)
@click.option("--agent", default="", help="Preferred coding agent.")
@click.option("--mode", default="readonly", type=click.Choice(["readonly"]))
@click.option("--file-ref", "file_refs", multiple=True, type=click.Path(path_type=Path))
@click.option("--fallback-agent", "fallback_agents", multiple=True, help="Fallback coding agent.")
@click.option("--capability", "capabilities", multiple=True, help="Optional TASK capability scope.")
@click.option("--max-turns", type=int, default=None)
@click.option("--max-budget-usd", type=float, default=None)
@click.option("--model", default="")
@click.option("--reasoning-effort", default="")
@click.option("--timeout-sec", type=float, default=None)
def dev_review(
    scope: tuple[str, ...],
    agent: str,
    mode: str,
    file_refs: tuple[Path, ...],
    fallback_agents: tuple[str, ...],
    capabilities: tuple[str, ...],
    max_turns: int | None,
    max_budget_usd: float | None,
    model: str,
    reasoning_effort: str,
    timeout_sec: float | None,
) -> None:
    """Dispatch a read-only review task through the daemon."""
    config = _get_config()
    result = rpc_call(
        config,
        "dev.review",
        _dev_task_payload(
            text_key="scope",
            text_value=_joined_text_arg(scope, field_name="scope"),
            agent=agent,
            file_refs=file_refs,
            fallback_agents=fallback_agents,
            capabilities=capabilities,
            max_turns=max_turns,
            max_budget_usd=max_budget_usd,
            model=model,
            reasoning_effort=reasoning_effort,
            timeout_sec=timeout_sec,
            extra={"mode": mode},
        ),
        response_model=DevReviewResult,
    )
    click.echo(_dump_model(result))


@dev.command("remediate")
@click.argument("findings", nargs=-1, required=True)
@click.option("--agent", default="", help="Preferred coding agent.")
@click.option("--file-ref", "file_refs", multiple=True, type=click.Path(path_type=Path))
@click.option("--fallback-agent", "fallback_agents", multiple=True, help="Fallback coding agent.")
@click.option("--capability", "capabilities", multiple=True, help="Optional TASK capability scope.")
@click.option("--max-turns", type=int, default=None)
@click.option("--max-budget-usd", type=float, default=None)
@click.option("--model", default="")
@click.option("--reasoning-effort", default="")
@click.option("--timeout-sec", type=float, default=None)
def dev_remediate(
    findings: tuple[str, ...],
    agent: str,
    file_refs: tuple[Path, ...],
    fallback_agents: tuple[str, ...],
    capabilities: tuple[str, ...],
    max_turns: int | None,
    max_budget_usd: float | None,
    model: str,
    reasoning_effort: str,
    timeout_sec: float | None,
) -> None:
    """Dispatch remediation against a findings bundle through the daemon."""
    config = _get_config()
    result = rpc_call(
        config,
        "dev.remediate",
        _dev_task_payload(
            text_key="findings",
            text_value=_joined_text_arg(findings, field_name="findings"),
            agent=agent,
            file_refs=file_refs,
            fallback_agents=fallback_agents,
            capabilities=capabilities,
            max_turns=max_turns,
            max_budget_usd=max_budget_usd,
            model=model,
            reasoning_effort=reasoning_effort,
            timeout_sec=timeout_sec,
        ),
        response_model=DevRemediateResult,
    )
    click.echo(_dump_model(result))


@dev.command("close")
@click.argument("milestone")
@click.option(
    "--implementation-doc",
    "implementation_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Override the implementation punchlist used for readiness checks.",
)
def dev_close(milestone: str, implementation_path: Path | None) -> None:
    """Report whether a milestone has the recorded evidence required for closure."""
    config = _get_config()
    payload: dict[str, object] = {"milestone": milestone}
    if implementation_path is not None:
        payload["implementation_path"] = str(implementation_path)
    result = rpc_call(
        config,
        "dev.close",
        payload,
        response_model=DevCloseResult,
    )
    click.echo(_dump_model(result))


# --- Session commands ---


@cli.group()
def session() -> None:
    """Manage sessions."""


@session.command("create")
@click.option("--user", "-u", default="", help="User ID")
@click.option("--workspace", "-w", default="", help="Workspace ID")
@click.option(
    "--mode",
    default="default",
    type=click.Choice(["default", "admin_cleanroom"]),
    help="Session mode.",
)
def session_create(user: str, workspace: str, mode: str) -> None:
    """Create a new session."""
    config = _get_config()

    result = rpc_call(
        config,
        "session.create",
        {"user_id": user, "workspace_id": workspace, "mode": mode},
        response_model=SessionCreateResult,
    )
    click.echo(f"Session created: {result.session_id} mode={result.mode}")


@session.command("message")
@click.argument("session_id")
@click.argument("content")
def session_message(session_id: str, content: str) -> None:
    """Send a message to a session."""
    config = _get_config()

    result = rpc_call(
        config,
        "session.message",
        {"session_id": session_id, "content": content},
        response_model=SessionMessageResult,
    )
    click.echo(
        render_evidence_refs_for_terminal(
            result.response,
            preserve_pending_preview_escapes=bool(result.pending_confirmation_ids),
        )
    )


@session.command("list")
def session_list() -> None:
    """List active sessions."""
    config = _get_config()

    result = rpc_call(config, "session.list", response_model=SessionListResult)
    if not result.sessions:
        click.echo("No active sessions")
        return
    for item in result.sessions:
        workspace = item.workspace_id or "-"
        lockdown = item.lockdown_level or "normal"
        click.echo(
            f"  {item.id}  state={item.state}  mode={item.mode}  "
            f"user={item.user_id}  workspace={workspace}  lockdown={lockdown}"
        )


@session.command("mode")
@click.argument("session_id")
@click.option(
    "--mode",
    required=True,
    type=click.Choice(["default", "admin_cleanroom"]),
    help="Target session mode.",
)
def session_mode(session_id: str, mode: str) -> None:
    """Set session execution mode."""
    config = _get_config()
    result = rpc_call(
        config,
        "session.set_mode",
        {"session_id": session_id, "mode": mode},
        response_model=SessionSetModeResult,
    )
    click.echo(_dump_model(result))


@session.command("grant-capabilities")
@click.argument("session_id")
@click.option(
    "--capability",
    "capabilities",
    multiple=True,
    required=True,
    help="Capability to grant (repeat for multiple values).",
)
@click.option("--reason", default="", help="Audit reason for capability grant.")
def session_grant_capabilities(
    session_id: str,
    capabilities: tuple[str, ...],
    reason: str,
) -> None:
    """Grant one or more capabilities to an active session."""
    config = _get_config()
    result = rpc_call(
        config,
        "session.grant_capabilities",
        {"session_id": session_id, "capabilities": list(capabilities), "reason": reason},
        response_model=SessionGrantCapabilitiesResult,
    )
    click.echo(_dump_model(result))


def _session_binding_payload_from_list(
    *,
    sessions: SessionListResult,
    session_id: str,
) -> dict[str, str]:
    for item in sessions.sessions:
        if item.id != session_id:
            continue
        return {
            "channel": item.channel or "",
            "user_id": item.user_id or "",
            "workspace_id": item.workspace_id or "",
        }
    raise click.ClickException(f"Session not found: {session_id}")


@session.command("terminate")
@click.argument("session_id")
@click.option("--reason", default="manual", help="Termination reason.")
def session_terminate(session_id: str, reason: str) -> None:
    """Terminate a session by ID."""
    config = _get_config()
    listed = rpc_call(config, "session.list", response_model=SessionListResult)
    binding = _session_binding_payload_from_list(sessions=listed, session_id=session_id)
    result = rpc_call(
        config,
        "session.terminate",
        {
            "session_id": session_id,
            "channel": binding["channel"],
            "user_id": binding["user_id"],
            "workspace_id": binding["workspace_id"],
            "reason": reason,
        },
        response_model=SessionTerminateResult,
    )
    click.echo(_dump_model(result))


@session.command("prune")
@click.option("--all", "prune_all", is_flag=True, help="Prune all active sessions.")
@click.option("--user", "user_id", default="", help="Prune sessions for a specific user_id.")
@click.option(
    "--older-than",
    default="",
    help="Prune sessions older than this duration (for example 24h, 7d).",
)
@click.option("--confirm", is_flag=True, help="Required with --all.")
def session_prune(prune_all: bool, user_id: str, older_than: str, confirm: bool) -> None:
    """Bulk-terminate sessions by filter."""
    if prune_all and not confirm:
        raise click.ClickException("--confirm is required with --all.")
    config = _get_config()
    listed = rpc_call(config, "session.list", response_model=SessionListResult)
    cutoff: datetime | None = None
    if older_than.strip():
        cutoff = datetime.now(UTC) - _parse_relative_duration(older_than)

    candidates = []
    for item in listed.sessions:
        if item.state.strip().lower() != "active":
            continue
        if user_id and item.user_id != user_id:
            continue
        if cutoff is not None:
            created_raw = (item.created_at or "").strip()
            if not created_raw:
                continue
            try:
                created = datetime.fromisoformat(created_raw)
            except ValueError:
                continue
            if created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            else:
                created = created.astimezone(UTC)
            if created > cutoff:
                continue
        if not prune_all and not user_id and cutoff is None:
            continue
        candidates.append(item)

    terminated = 0
    for item in candidates:
        result = rpc_call(
            config,
            "session.terminate",
            {
                "session_id": item.id,
                "channel": item.channel,
                "user_id": item.user_id,
                "workspace_id": item.workspace_id,
                "reason": "prune",
            },
            response_model=SessionTerminateResult,
        )
        if result.terminated:
            terminated += 1
    click.echo(f"Pruned {terminated}/{len(candidates)} sessions")


@session.command("restore")
@click.argument("checkpoint_id")
def session_restore(checkpoint_id: str) -> None:
    """Restore a session from a checkpoint ID."""
    config = _get_config()

    result = rpc_call(
        config,
        "session.restore",
        {"checkpoint_id": checkpoint_id},
        response_model=SessionRestoreResult,
    )
    if result.restored:
        click.echo(f"Restored session {result.session_id} from checkpoint {checkpoint_id}")
        return
    if result.reason in {"", "not_found"}:
        click.echo(f"Checkpoint not found: {checkpoint_id}", err=True)
    else:
        click.echo(
            f"Session restore failed: {result.reason} (checkpoint {checkpoint_id})",
            err=True,
        )
    sys.exit(1)


@session.command("export")
@click.argument("session_id")
@click.argument("output_path", required=False)
def session_export(session_id: str, output_path: str | None) -> None:
    """Export a bounded single-session archive."""
    config = _get_config()
    payload: dict[str, object] = {"session_id": session_id}
    if output_path:
        payload["path"] = output_path
    result = rpc_call(
        config,
        "session.export",
        payload,
        response_model=SessionExportResult,
    )
    if result.exported:
        click.echo(
            f"Exported session {result.session_id} to {result.archive_path} "
            "("
            f"checkpoints={result.checkpoint_count}, "
            f"transcript_entries={result.transcript_entries}"
            ")"
        )
        return
    click.echo(f"Session export failed: {result.reason}", err=True)
    sys.exit(1)


@session.command("import")
@click.argument("archive_path")
def session_import(archive_path: str) -> None:
    """Import a bounded single-session archive into a fresh session."""
    config = _get_config()

    result = rpc_call(
        config,
        "session.import",
        {"archive_path": archive_path},
        response_model=SessionImportResult,
    )
    if result.imported:
        click.echo(
            f"Imported archive {result.archive_path} as session {result.session_id} "
            f"(from {result.original_session_id}, checkpoints={result.checkpoint_count})"
        )
        return
    click.echo(f"Session import failed: {result.reason}", err=True)
    sys.exit(1)


@session.command("rollback")
@click.argument("checkpoint_id")
def session_rollback(checkpoint_id: str) -> None:
    """Rollback a session to a checkpoint ID."""
    config = _get_config()

    result = rpc_call(
        config,
        "session.rollback",
        {"checkpoint_id": checkpoint_id},
        response_model=SessionRollbackResult,
    )
    if result.rolled_back:
        click.echo(f"Rolled back session {result.session_id} to checkpoint {checkpoint_id}")
        return
    if result.reason in {"", "not_found"}:
        click.echo(f"Checkpoint not found: {checkpoint_id}", err=True)
    else:
        click.echo(
            f"Session rollback failed: {result.reason} (checkpoint {checkpoint_id})",
            err=True,
        )
    sys.exit(1)


# --- Audit commands ---


@cli.group()
def audit() -> None:
    """Query the audit log."""


@audit.command("query")
@click.option("--since", help="Show events since (e.g., '1h', '2025-01-01')")
@click.option("--type", "event_type", help="Filter by event type")
@click.option("--session", "session_id", help="Filter by session ID")
@click.option("--actor", "actor", help="Filter by actor")
@click.option("--limit", default=100, help="Maximum results")
def audit_query(
    since: str | None,
    event_type: str | None,
    session_id: str | None,
    actor: str | None,
    limit: int,
) -> None:
    """Query audit log entries."""
    config = _get_config()
    audit_path = config.data_dir / "audit.jsonl"

    if not audit_path.exists():
        click.echo("No audit log found")
        return

    from shisad.core.audit import AuditLog

    log = AuditLog(audit_path)
    try:
        since_dt = AuditLog.parse_since(since)
    except ValueError as e:
        click.echo(f"Invalid --since value: {e}", err=True)
        sys.exit(1)
    results = log.query(
        since=since_dt,
        event_type=event_type,
        session_id=session_id,
        actor=actor,
        limit=limit,
    )

    if not results:
        click.echo("No matching events")
        return

    for entry in results:
        ts = entry.get("timestamp", "")
        et = entry.get("event_type", "")
        sid = entry.get("session_id", "—")
        act = entry.get("actor", "—")
        click.echo(f"  {ts}  {et:20s}  session={sid}  actor={act}")


@audit.command("verify")
def audit_verify() -> None:
    """Verify audit log integrity."""
    config = _get_config()
    audit_path = config.data_dir / "audit.jsonl"

    if not audit_path.exists():
        click.echo("No audit log found")
        return

    from shisad.core.audit import AuditLog

    log = AuditLog(audit_path)
    is_valid, count, error = log.verify_chain()

    if is_valid:
        click.echo(f"Audit log integrity verified: {count} entries, chain intact")
    else:
        click.echo(f"INTEGRITY FAILURE at entry {count}: {error}", err=True)
        sys.exit(1)


@cli.group()
def events() -> None:
    """Subscribe to daemon event stream."""


@events.command("subscribe")
@click.option("--event-type", "event_types", multiple=True, help="Filter by event type")
@click.option("--session", "session_id", help="Filter by session id")
@click.option("--count", default=0, help="Stop after N events (0 = stream forever)")
def events_subscribe(
    event_types: tuple[str, ...],
    session_id: str | None,
    count: int,
) -> None:
    """Stream events from the daemon."""
    config = _get_config()

    async def _subscribe(client: Any) -> None:
        received = 0
        params: dict[str, object] = {}
        if event_types:
            params["event_types"] = list(event_types)
        if session_id:
            params["session_id"] = session_id
        await client.subscribe_events(params)
        while True:
            event = await client.read_event()
            click.echo(json.dumps(event, sort_keys=True))
            received += 1
            if count > 0 and received >= count:
                break

    try:
        rpc_run(config, _subscribe, action="events.subscribe")
    except KeyboardInterrupt:
        return


@cli.group()
def action() -> None:
    """Pending action review and decision commands."""


@action.command("pending")
@click.option("--session", "session_id", default="", help="Filter by session id")
@click.option("--status", default="", help="Filter by status")
@click.option("--limit", default=50, help="Maximum rows")
@click.option("--raw", is_flag=True, help="Disable UI preview payloads")
def action_pending(session_id: str, status: str, limit: int, raw: bool) -> None:
    """List pending confirmations."""
    config = _get_config()
    result = rpc_call(
        config,
        "action.pending",
        {
            "session_id": session_id or None,
            "status": status or None,
            "limit": limit,
            "include_ui": not raw,
        },
        response_model=ActionPendingResult,
    )
    rows = result.actions
    if not rows:
        _echo("No pending confirmations", fg="yellow")
        return
    for row in rows:
        confirmation_id = sanitize_terminal_field(row.confirmation_id)
        nonce_value = sanitize_terminal_field(row.decision_nonce or "")
        status_value = sanitize_terminal_field(row.status)
        tool_name = sanitize_terminal_field(row.tool_name)
        reason_value = sanitize_terminal_field(row.reason)
        click.echo(
            f"{confirmation_id} nonce={nonce_value} status={status_value} "
            f"tool={tool_name} reason={reason_value}"
        )
        preview = sanitize_terminal_text(row.safe_preview or "").strip()
        if preview:
            click.echo(preview)
        approval_url = sanitize_terminal_field(row.approval_url or "")
        if approval_url:
            click.echo(f"approval_url={approval_url}")
        approval_qr_ascii = (row.approval_qr_ascii or "").rstrip()
        if approval_qr_ascii:
            click.echo("approval_qr:")
            click.echo(approval_qr_ascii)
        if preview or approval_url or approval_qr_ascii:
            click.echo("")


def _pending_action_row(
    *,
    config: DaemonConfig,
    confirmation_id: str,
    status: str = "",
    include_ui: bool = True,
) -> ActionPendingEntry | None:
    pending = rpc_call(
        config,
        "action.pending",
        {
            "confirmation_id": confirmation_id,
            "status": status or None,
            "limit": 1,
            "include_ui": include_ui,
        },
        response_model=ActionPendingResult,
    )
    for row in pending.actions:
        if row.confirmation_id != confirmation_id:
            continue
        return row
    return None


def _resolve_pending_decision_nonce(
    *,
    config: DaemonConfig,
    confirmation_id: str,
) -> str:
    pending = _pending_action_row(
        config=config,
        confirmation_id=confirmation_id,
        status="pending",
        include_ui=False,
    )
    return (pending.decision_nonce or "").strip() if pending is not None else ""


def _synthetic_pending_confirm_result(row: ActionPendingEntry) -> ActionConfirmResult:
    return ActionConfirmResult(
        confirmed=row.status == "approved",
        confirmation_id=row.confirmation_id,
        decision_nonce=row.decision_nonce or None,
        status=row.status or None,
        status_reason=row.status_reason,
        reason=None if row.status == "approved" else row.status_reason,
        approval_level=row.required_level or None,
        approval_method=row.selected_backend_method or None,
    )


def _wait_for_pending_action_resolution(
    *,
    config: DaemonConfig,
    confirmation_id: str,
    timeout_seconds: float,
    poll_interval_seconds: float = 1.0,
) -> ActionPendingEntry:
    deadline = time.monotonic() + timeout_seconds
    latest: ActionPendingEntry | None = None
    while True:
        latest = _pending_action_row(
            config=config,
            confirmation_id=confirmation_id,
            include_ui=False,
        )
        if latest is not None and latest.status.lower() != "pending":
            return latest
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_interval_seconds, remaining))
    detail = latest.status if latest is not None else "not_found"
    raise click.ClickException(
        f"Timed out waiting for browser approval on {confirmation_id} (last status: {detail})."
    )


def _wait_for_registered_factor(
    *,
    config: DaemonConfig,
    user_id: str,
    method: str,
    credential_id: str,
    timeout_seconds: float,
    poll_interval_seconds: float = 1.0,
) -> TwoFactorEntry:
    deadline = time.monotonic() + timeout_seconds
    while True:
        listed = rpc_call(
            config,
            "2fa.list",
            {"user_id": user_id, "method": method},
            response_model=TwoFactorListResult,
        )
        for entry in listed.entries:
            if entry.credential_id == credential_id:
                return entry
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_interval_seconds, remaining))
    raise click.ClickException(
        f"Timed out waiting for {method} factor {credential_id} to finish registration."
    )


def _open_browser_url(url: str) -> None:
    launched = click.launch(url, locate=False)
    if launched is False:
        _echo("Automatic browser launch failed; open the URL manually.", fg="yellow", err=True)


def _resolved_approval_setup_config(
    *,
    config: DaemonConfig,
    origin: str,
    bind_host: str,
    bind_port: int | None,
    rp_id: str,
) -> DaemonConfig:
    payload = config.model_dump(mode="python")
    if origin.strip():
        payload["approval_origin"] = origin.strip()
    if bind_host.strip():
        payload["approval_bind_host"] = bind_host.strip()
    if bind_port is not None:
        payload["approval_bind_port"] = bind_port
    if rp_id.strip():
        payload["approval_rp_id"] = rp_id.strip()
    return DaemonConfig.model_validate(payload)


@action.command("confirm")
@click.argument("confirmation_id")
@click.option("--nonce", default="", help="Decision nonce for replay-safe confirmation")
@click.option("--reason", default="", help="Operator note")
@click.option("--approval-method", default="", help="Explicit approval method override.")
@click.option("--principal-id", default="", help="Explicit approver principal id.")
@click.option("--credential-id", default="", help="Explicit credential id.")
@click.option("--totp-code", default="", help="TOTP code for reauthenticated approvals.")
@click.option("--recovery-code", default="", help="Single-use recovery code for L1 approvals.")
@click.option("--no-open", is_flag=True, help="Print the browser URL but do not auto-open it.")
@click.option(
    "--wait-timeout",
    default=180.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Seconds to wait for browser-based approval to complete.",
)
def action_confirm(
    confirmation_id: str,
    nonce: str,
    reason: str,
    approval_method: str,
    principal_id: str,
    credential_id: str,
    totp_code: str,
    recovery_code: str,
    no_open: bool,
    wait_timeout: float,
) -> None:
    """Approve one pending confirmation."""
    config = _get_config()
    pending_row = _pending_action_row(
        config=config,
        confirmation_id=confirmation_id,
        status="pending",
        include_ui=True,
    )
    decision_nonce = nonce.strip()
    if not decision_nonce:
        decision_nonce = (pending_row.decision_nonce or "").strip() if pending_row else ""
    if not decision_nonce:
        existing_row = _pending_action_row(
            config=config,
            confirmation_id=confirmation_id,
            include_ui=False,
        )
        if existing_row is not None and existing_row.status.lower() != "pending":
            click.echo(_dump_model(_synthetic_pending_confirm_result(existing_row)))
            return
        raise click.ClickException(
            "Decision nonce not found for confirmation_id; run 'shisad action pending' and retry "
            "with --nonce."
        )
    if totp_code.strip() and recovery_code.strip():
        raise click.ClickException("Use either --totp-code or --recovery-code, not both.")
    payload: dict[str, object] = {
        "confirmation_id": confirmation_id,
        "decision_nonce": decision_nonce,
        "reason": reason,
    }
    method_value = approval_method.strip()
    principal_value = principal_id.strip()
    credential_value = credential_id.strip()
    selected_backend_method = (
        (pending_row.selected_backend_method or "").strip() if pending_row else ""
    )
    if principal_value:
        payload["principal_id"] = principal_value
    if credential_value:
        payload["credential_id"] = credential_value
    if totp_code.strip():
        if method_value and method_value != "totp":
            raise click.ClickException("--approval-method conflicts with --totp-code.")
        payload["approval_method"] = "totp"
        payload["proof"] = {"totp_code": totp_code.strip()}
    elif recovery_code.strip():
        if method_value and method_value != "recovery_code":
            raise click.ClickException("--approval-method conflicts with --recovery-code.")
        payload["approval_method"] = "recovery_code"
        payload["proof"] = {"recovery_code": recovery_code.strip()}
    elif selected_backend_method == "webauthn":
        if method_value and method_value != "webauthn":
            raise click.ClickException(
                "--approval-method conflicts with the pending WebAuthn approval flow."
            )
        approval_url = (pending_row.approval_url or "").strip() if pending_row else ""
        if not approval_url:
            raise click.ClickException(
                "WebAuthn approval URL unavailable; run 'shisad action pending' and retry."
            )
        click.echo(f"Open this approval URL in a system browser:\n{approval_url}")
        approval_qr_ascii = (pending_row.approval_qr_ascii or "").rstrip() if pending_row else ""
        if approval_qr_ascii:
            click.echo("QR:")
            click.echo(approval_qr_ascii)
        if not no_open:
            _open_browser_url(approval_url)
        _echo(f"Waiting for browser approval ({wait_timeout:.0f}s timeout)", fg="cyan")
        resolved_row = _wait_for_pending_action_resolution(
            config=config,
            confirmation_id=confirmation_id,
            timeout_seconds=wait_timeout,
        )
        click.echo(_dump_model(_synthetic_pending_confirm_result(resolved_row)))
        return
    elif method_value:
        payload["approval_method"] = method_value
    result = rpc_call(
        config,
        "action.confirm",
        payload,
        response_model=ActionConfirmResult,
    )
    click.echo(_dump_model(result))


@action.command("reject")
@click.argument("confirmation_id")
@click.option("--nonce", default="", help="Decision nonce for replay-safe rejection")
@click.option("--reason", default="manual_reject", help="Rejection reason")
def action_reject(confirmation_id: str, nonce: str, reason: str) -> None:
    """Reject one pending confirmation."""
    config = _get_config()
    decision_nonce = nonce.strip()
    if not decision_nonce:
        decision_nonce = _resolve_pending_decision_nonce(
            config=config,
            confirmation_id=confirmation_id,
        )
    if not decision_nonce:
        raise click.ClickException(
            "Decision nonce not found for confirmation_id; run 'shisad action pending' and retry "
            "with --nonce."
        )
    result = rpc_call(
        config,
        "action.reject",
        {
            "confirmation_id": confirmation_id,
            "decision_nonce": decision_nonce,
            "reason": reason,
        },
        response_model=ActionRejectResult,
    )
    click.echo(_dump_model(result))


@cli.group("2fa")
def two_factor() -> None:
    """Manage operator approval factors."""


@two_factor.command("register")
@click.option(
    "--method",
    default="totp",
    type=click.Choice(["totp", "webauthn"]),
    show_default=True,
    help="Approval method to enroll.",
)
@click.option("--user", "user_id", required=True, help="Target user ID.")
@click.option("--name", default="", help="Audit principal label (defaults to local username).")
@click.option("--no-open", is_flag=True, help="Print the browser URL but do not auto-open it.")
@click.option(
    "--wait-timeout",
    default=180.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Seconds to wait for browser-based registration to complete.",
)
def two_factor_register(
    method: str,
    user_id: str,
    name: str,
    no_open: bool,
    wait_timeout: float,
) -> None:
    """Enroll a new approval factor and verify it before activation."""
    config = _get_config()
    begin = rpc_call(
        config,
        "2fa.register_begin",
        {
            "method": method,
            "user_id": user_id,
            "name": name.strip() or None,
        },
        response_model=TwoFactorRegisterBeginResult,
    )
    if not begin.started:
        raise click.ClickException(begin.reason or "2fa enrollment could not be started")
    click.echo(f"User: {begin.user_id}")
    click.echo(f"Method: {begin.method}")
    click.echo(f"Principal: {begin.principal_id}")
    click.echo(f"Credential: {begin.credential_id}")
    if begin.expires_at:
        click.echo(f"Enrollment expires at: {begin.expires_at}")
    if begin.method == "webauthn":
        registration_url = begin.registration_url.strip()
        if not registration_url:
            raise click.ClickException(begin.reason or "WebAuthn registration URL is unavailable")
        click.echo(f"Registration URL: {registration_url}")
        click.echo(f"Approval origin: {begin.approval_origin}")
        click.echo(f"rp_id: {begin.rp_id}")
        if not no_open:
            _open_browser_url(registration_url)
        _echo(f"Waiting for browser registration ({wait_timeout:.0f}s timeout)", fg="cyan")
        registered = _wait_for_registered_factor(
            config=config,
            user_id=begin.user_id,
            method=begin.method,
            credential_id=begin.credential_id,
            timeout_seconds=wait_timeout,
        )
        click.echo(
            f"Registered {registered.method} factor {registered.credential_id} for "
            f"{registered.user_id}"
        )
        return
    click.echo(f"Secret: {begin.secret}")
    click.echo(f"otpauth URI: {begin.otpauth_uri}")
    qr_ascii = _render_terminal_qr(begin.otpauth_uri)
    if qr_ascii:
        click.echo("Scan this QR in your authenticator app:")
        click.echo(qr_ascii)
    verify_code = click.prompt("Verification code").strip()
    confirm = rpc_call(
        config,
        "2fa.register_confirm",
        {
            "enrollment_id": begin.enrollment_id,
            "verify_code": verify_code,
        },
        response_model=TwoFactorRegisterConfirmResult,
    )
    if not confirm.registered:
        raise click.ClickException(confirm.reason or "2fa enrollment verification failed")
    click.echo(f"Registered {confirm.method} factor {confirm.credential_id} for {confirm.user_id}")
    if confirm.recovery_codes:
        click.echo("Recovery codes:")
        for code in confirm.recovery_codes:
            click.echo(code)


@two_factor.command("list")
@click.option("--user", "user_id", default="", help="Filter by user ID.")
@click.option("--method", default="", help="Filter by method.")
def two_factor_list(user_id: str, method: str) -> None:
    """List enrolled approval factors."""
    config = _get_config()
    result = rpc_call(
        config,
        "2fa.list",
        {
            "user_id": user_id or None,
            "method": method or None,
        },
        response_model=TwoFactorListResult,
    )
    if not result.entries:
        click.echo("No registered 2FA factors")
        return
    for entry in result.entries:
        click.echo(
            f"{entry.user_id} method={entry.method} principal={entry.principal_id} "
            f"credential={entry.credential_id} recovery_codes={entry.recovery_codes_remaining}"
        )


@two_factor.command("revoke")
@click.option(
    "--method",
    default="totp",
    type=click.Choice(["totp", "webauthn", "local_fido2"]),
    show_default=True,
    help="Approval method to revoke.",
)
@click.option("--user", "user_id", required=True, help="Target user ID.")
@click.option("--credential-id", default="", help="Optional credential ID to revoke.")
def two_factor_revoke(method: str, user_id: str, credential_id: str) -> None:
    """Revoke one or more enrolled approval factors."""
    config = _get_config()
    result = rpc_call(
        config,
        "2fa.revoke",
        {
            "method": method,
            "user_id": user_id,
            "credential_id": credential_id or None,
        },
        response_model=TwoFactorRevokeResult,
    )
    if not result.revoked:
        raise click.ClickException(result.reason or "matching 2FA factor not found")
    click.echo(f"Revoked {result.removed} factor(s) for {user_id}")


@cli.group("signer")
def signer() -> None:
    """Manage authorization-grade signer keys."""


@signer.command("register")
@click.option(
    "--backend",
    default="kms",
    type=click.Choice(["kms"]),
    show_default=True,
    help="Signer backend type.",
)
@click.option("--user", "user_id", required=True, help="Target user ID.")
@click.option("--key-id", required=True, help="Stable signer key identifier.")
@click.option("--name", default="", help="Audit principal label (defaults to local username).")
@click.option(
    "--algorithm",
    default="ed25519",
    type=click.Choice(["ed25519", "ecdsa-secp256k1"]),
    show_default=True,
    help="Signature algorithm for the registered public key.",
)
@click.option(
    "--device-type",
    default="ledger-enterprise",
    show_default=True,
    help="Signer device or provider type label.",
)
@click.option(
    "--public-key",
    "public_key_path",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    required=True,
    help="PEM-encoded public key for signature verification.",
)
def signer_register(
    backend: str,
    user_id: str,
    key_id: str,
    name: str,
    algorithm: str,
    device_type: str,
    public_key_path: Path,
) -> None:
    """Register a signer key for approval policies."""
    config = _get_config()
    result = rpc_call(
        config,
        "signer.register",
        {
            "backend": backend,
            "user_id": user_id,
            "key_id": key_id,
            "name": name.strip() or None,
            "algorithm": algorithm,
            "device_type": device_type.strip() or "ledger-enterprise",
            "public_key_pem": public_key_path.read_text(encoding="utf-8"),
        },
        response_model=SignerRegisterResult,
    )
    if not result.registered:
        raise click.ClickException(result.reason or "signer registration failed")
    click.echo(
        f"Registered signer key {result.credential_id} "
        f"({result.algorithm}, {result.device_type}) for {result.user_id}"
    )


@signer.command("list")
@click.option("--user", "user_id", default="", help="Filter by user ID.")
@click.option(
    "--backend",
    default="",
    type=click.Choice(["kms"], case_sensitive=False),
    help="Optional backend filter.",
)
@click.option("--include-revoked", is_flag=True, help="Include revoked signer keys.")
def signer_list(user_id: str, backend: str, include_revoked: bool) -> None:
    """List registered signer keys."""
    config = _get_config()
    result = rpc_call(
        config,
        "signer.list",
        {
            "user_id": user_id or None,
            "backend": backend or None,
            "include_revoked": include_revoked,
        },
        response_model=SignerListResult,
    )
    if not result.entries:
        click.echo("No registered signer keys")
        return
    for entry in result.entries:
        click.echo(
            f"{entry.user_id} backend={entry.backend} principal={entry.principal_id} "
            f"credential={entry.credential_id} algorithm={entry.algorithm} "
            f"device_type={entry.device_type} revoked={entry.revoked}"
        )


@signer.command("revoke")
@click.option("--key-id", required=True, help="Signer key identifier to revoke.")
def signer_revoke(key_id: str) -> None:
    """Revoke a registered signer key."""
    config = _get_config()
    result = rpc_call(
        config,
        "signer.revoke",
        {"key_id": key_id},
        response_model=SignerRevokeResult,
    )
    if not result.revoked:
        raise click.ClickException(result.reason or "signer key not found")
    click.echo(f"Revoked signer key {key_id}")


@cli.group()
def approval() -> None:
    """Approval-origin setup helpers and browser UX guidance."""


@approval.command("setup")
@click.option(
    "--provider",
    default="caddy",
    show_default=True,
    type=click.Choice(["caddy", "tailscale"]),
    help="Provisioning helper to print.",
)
@click.option(
    "--origin",
    default="",
    help="Approval origin override (for example https://approve.example.com).",
)
@click.option("--rp-id", default="", help="Optional WebAuthn rpId override.")
@click.option("--bind-host", default="", help="Daemon listener host override.")
@click.option("--bind-port", type=int, default=None, help="Daemon listener port override.")
def approval_setup(
    provider: str,
    origin: str,
    rp_id: str,
    bind_host: str,
    bind_port: int | None,
) -> None:
    """Print approval-origin env vars plus reverse-proxy guidance."""
    config = _get_config()
    effective = _resolved_approval_setup_config(
        config=config,
        origin=origin,
        bind_host=bind_host,
        bind_port=bind_port,
        rp_id=rp_id,
    )
    if not effective.approval_origin:
        raise click.ClickException(
            "Set SHISAD_APPROVAL_ORIGIN or pass --origin before using approval setup."
        )
    parsed = urlparse(effective.approval_origin)
    if parsed.scheme != "https":
        raise click.ClickException(f"{provider} approval setup expects an https approval origin.")
    click.echo("Environment:")
    click.echo(f"export SHISAD_APPROVAL_ORIGIN={effective.approval_origin}")
    click.echo(f"export SHISAD_APPROVAL_RP_ID={effective.approval_rp_id}")
    click.echo(f"export SHISAD_APPROVAL_BIND_HOST={effective.approval_bind_host}")
    click.echo(f"export SHISAD_APPROVAL_BIND_PORT={effective.approval_bind_port}")
    click.echo("")
    if provider == "caddy":
        click.echo("Caddyfile:")
        click.echo(f"{parsed.netloc} {{")
        click.echo(
            f"    reverse_proxy {effective.approval_bind_host}:{effective.approval_bind_port}"
        )
        click.echo("}")
        return
    click.echo("Tailscale Guidance:")
    click.echo(f"Use {effective.approval_origin} as the HTTPS tailnet origin.")
    click.echo(
        "Expose the daemon listener below through your preferred Tailscale HTTPS path "
        "(for example serve/funnel on the same hostname):"
    )
    click.echo(f"http://{effective.approval_bind_host}:{effective.approval_bind_port}")


@cli.group()
def lockdown() -> None:
    """Manual lockdown controls."""


@lockdown.command("resume")
@click.argument("session_id")
@click.option("--reason", default="manual", help="Operator note")
def lockdown_resume(session_id: str, reason: str) -> None:
    """Resume a session to normal lockdown level."""
    config = _get_config()
    result = rpc_call(
        config,
        "lockdown.set",
        {"session_id": session_id, "action": "resume", "reason": reason},
        response_model=LockdownSetResult,
    )
    click.echo(_dump_model(result))


@lockdown.command("set")
@click.argument("session_id")
@click.option(
    "--action",
    "action_name",
    required=True,
    type=click.Choice(["resume", "caution", "quarantine"], case_sensitive=False),
)
@click.option("--reason", default="manual", help="Operator note")
def lockdown_set(session_id: str, action_name: str, reason: str) -> None:
    """Set lockdown level for a session."""
    config = _get_config()
    result = rpc_call(
        config,
        "lockdown.set",
        {"session_id": session_id, "action": action_name, "reason": reason},
        response_model=LockdownSetResult,
    )
    click.echo(_dump_model(result))


@cli.group()
def channel() -> None:
    """Channel admin workflows."""


@channel.command("pairing-propose")
@click.option("--channel", "channel_name", default="", help="Optional channel filter")
@click.option("--workspace", "workspace_hint", default="", help="Optional workspace hint filter")
@click.option("--limit", default=100, help="Maximum proposal entries")
def channel_pairing_propose(channel_name: str, workspace_hint: str, limit: int) -> None:
    """Generate proposal-only channel allowlist patch from pairing artifacts."""
    config = _get_config()
    result = rpc_call(
        config,
        "channel.pairing_propose",
        {
            "channel": channel_name or None,
            "workspace_hint": workspace_hint or None,
            "limit": limit,
        },
        response_model=ChannelPairingProposalResult,
    )
    click.echo(_dump_model(result))


@cli.group()
def dashboard() -> None:
    """Security dashboard and incident-review queries."""


@dashboard.command("audit")
@click.option("--since", default="", help="Since filter (e.g. 1h)")
@click.option("--type", "event_type", default="", help="Event type filter")
@click.option("--session", "session_id", default="", help="Session id filter")
@click.option("--actor", default="", help="Actor filter")
@click.option("--search", "text_search", default="", help="Full-text search")
@click.option("--limit", default=100, help="Maximum rows")
def dashboard_audit(
    since: str,
    event_type: str,
    session_id: str,
    actor: str,
    text_search: str,
    limit: int,
) -> None:
    """Audit explorer with hash-chain status."""
    config = _get_config()
    result = rpc_call(
        config,
        "dashboard.audit_explorer",
        {
            "since": since or None,
            "event_type": event_type or None,
            "session_id": session_id or None,
            "actor": actor or None,
            "text_search": text_search,
            "limit": limit,
        },
        response_model=DashboardQueryResult,
    )
    chain = result.hash_chain or {}
    click.echo(f"hash_chain valid={chain.get('valid')} checked={chain.get('entries_checked')}")
    for event in result.events:
        click.echo(
            f"{event.timestamp} {event.event_type} session={event.session_id} actor={event.actor}"
        )


@dashboard.command("egress")
@click.option("--limit", default=100, help="Maximum rows")
def dashboard_egress(limit: int) -> None:
    """Review blocked/flagged egress attempts."""
    config = _get_config()
    result = rpc_call(
        config,
        "dashboard.egress_review",
        {"limit": limit},
        response_model=DashboardQueryResult,
    )
    for event in result.events:
        click.echo(
            f"{event.timestamp} host={event.data.get('destination_host', '')} "
            f"allowed={event.data.get('allowed')} reason={event.data.get('reason', '')}"
        )


@dashboard.command("skill-provenance")
@click.option("--limit", default=100, help="Maximum rows")
def dashboard_skill_provenance(limit: int) -> None:
    """View skill installation/review/profile/revocation/drift timeline."""
    config = _get_config()
    result = rpc_call(
        config,
        "dashboard.skill_provenance",
        {"limit": limit},
        response_model=DashboardQueryResult,
    )
    for row in result.timeline:
        click.echo(f"{row.skill_name} versions={','.join(row.versions)}")
        for event in row.events:
            parts = [
                str(event.get("timestamp", "")).strip(),
                str(event.get("event_type", "")).strip(),
            ]
            status = str(event.get("status", "")).strip()
            if status:
                parts.append(f"status={status}")
            signature_status = str(event.get("signature_status", "")).strip()
            if signature_status:
                parts.append(f"signature={signature_status}")
            tool_name = str(event.get("tool_name", "")).strip()
            if tool_name:
                parts.append(f"tool={tool_name}")
            reason_code = str(event.get("reason_code", "")).strip()
            if reason_code:
                parts.append(f"reason={reason_code}")
            registration_source = str(event.get("registration_source", "")).strip()
            if registration_source:
                parts.append(f"source={registration_source}")
            expected_hash_prefix = str(event.get("expected_hash_prefix", "")).strip()
            if expected_hash_prefix:
                parts.append(f"expected={expected_hash_prefix}")
            actual_hash_prefix = str(event.get("actual_hash_prefix", "")).strip()
            if actual_hash_prefix:
                parts.append(f"actual={actual_hash_prefix}")
            click.echo("  " + " ".join(part for part in parts if part))


@dashboard.command("alerts")
@click.option("--limit", default=100, help="Maximum rows")
def dashboard_alerts(limit: int) -> None:
    """List active/recent alerts."""
    config = _get_config()
    result = rpc_call(
        config,
        "dashboard.alerts",
        {"limit": limit},
        response_model=DashboardQueryResult,
    )
    for row in result.alerts:
        click.echo(f"{row.event_id} {row.event_type} ack={row.acknowledged_reason}")


@dashboard.command("mark-fp")
@click.argument("event_id")
@click.option("--reason", default="false_positive", help="Acknowledgment reason")
def dashboard_mark_fp(event_id: str, reason: str) -> None:
    """Mark a dashboard alert as false-positive/acknowledged."""
    config = _get_config()
    result = rpc_call(
        config,
        "dashboard.mark_false_positive",
        {"event_id": event_id, "reason": reason},
        response_model=DashboardMarkFalsePositiveResult,
    )
    click.echo(_dump_model(result))


@cli.group()
def confirmation() -> None:
    """Confirmation analytics and hygiene checks."""


@confirmation.command("metrics")
@click.option("--user", "user_id", default="", help="User filter")
@click.option("--window", "window_seconds", default=900, help="Window in seconds")
def confirmation_metrics(user_id: str, window_seconds: int) -> None:
    """Show confirmation hygiene metrics."""
    config = _get_config()
    result = rpc_call(
        config,
        "confirmation.metrics",
        {"user_id": user_id or None, "window_seconds": window_seconds},
        response_model=ConfirmationMetricsResult,
    )
    click.echo(_dump_model(result))


@cli.group()
def memory() -> None:
    """Memory manager operations."""


@memory.command("list")
@click.option("--limit", default=100, help="Maximum entries")
def memory_list(limit: int) -> None:
    config = _get_config()
    result = rpc_call(config, "memory.list", {"limit": limit}, response_model=MemoryListResult)
    for item in result.entries:
        click.echo(f"{item.id} {item.entry_type} {item.key}")


@memory.command("write")
@click.option(
    "--type",
    "entry_type",
    required=True,
    type=click.Choice(["fact", "preference", "context"]),
)
@click.option("--key", required=True)
@click.option("--value", required=True)
@click.option("--origin", default="user", type=click.Choice(["user", "external", "inferred"]))
@click.option("--source-id", default="cli")
@click.option("--confirm", is_flag=True, help="Confirm external/suspicious writes")
def memory_write(
    entry_type: str,
    key: str,
    value: str,
    origin: str,
    source_id: str,
    confirm: bool,
) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "memory.write",
        {
            "entry_type": entry_type,
            "key": key,
            "value": value,
            "source": {
                "origin": origin,
                "source_id": source_id,
                "extraction_method": "cli",
            },
            "user_confirmed": confirm,
        },
        response_model=MemoryWriteResult,
    )
    click.echo(_dump_model(result))


@memory.command("rotate-key")
@click.option(
    "--no-reencrypt",
    is_flag=True,
    help="Rotate active key only (do not re-encrypt existing records).",
)
def memory_rotate_key(no_reencrypt: bool) -> None:
    """Rotate memory/retrieval encryption key material."""
    config = _get_config()
    result = rpc_call(
        config,
        "memory.rotate_key",
        {"reencrypt_existing": not no_reencrypt},
        response_model=MemoryRotateKeyResult,
    )
    click.echo(_dump_model(result))


@cli.group()
def note() -> None:
    """First-class note operations."""


@note.command("create")
@click.option("--key", required=True)
@click.option("--content", required=True)
@click.option("--origin", default="user", type=click.Choice(["user", "external", "inferred"]))
@click.option("--source-id", default="cli")
@click.option("--confirm", is_flag=True, help="Confirm external/suspicious writes")
def note_create(key: str, content: str, origin: str, source_id: str, confirm: bool) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "note.create",
        {
            "key": key,
            "content": content,
            "origin": origin,
            "source_id": source_id,
            "user_confirmed": confirm,
        },
        response_model=MemoryWriteResult,
    )
    click.echo(_dump_model(result))


@note.command("list")
@click.option("--limit", default=100, help="Maximum entries")
def note_list(limit: int) -> None:
    config = _get_config()
    result = rpc_call(config, "note.list", {"limit": limit}, response_model=NoteListResult)
    for item in result.entries:
        click.echo(f"{item.get('id', '')} {item.get('key', '')}")


@note.command("get")
@click.argument("entry_id")
def note_get(entry_id: str) -> None:
    config = _get_config()
    result = rpc_call(config, "note.get", {"entry_id": entry_id}, response_model=NoteGetResult)
    click.echo(_dump_model(result))


@note.command("delete")
@click.argument("entry_id")
def note_delete(entry_id: str) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "note.delete",
        {"entry_id": entry_id},
        response_model=NoteDeleteResult,
    )
    click.echo(_dump_model(result))


@note.command("verify")
@click.argument("entry_id")
def note_verify(entry_id: str) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "note.verify",
        {"entry_id": entry_id},
        response_model=NoteVerifyResult,
    )
    click.echo(_dump_model(result))


@note.command("export")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "csv"]))
def note_export(fmt: str) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "note.export",
        {"format": fmt},
        response_model=NoteExportResult,
    )
    click.echo(str(result.data))


@cli.group()
def todo() -> None:
    """First-class todo operations."""


@todo.command("create")
@click.option("--title", required=True)
@click.option("--details", default="")
@click.option("--status", default="open", type=click.Choice(["open", "in_progress", "done"]))
@click.option("--due-date", default="", help="Optional due date string")
@click.option("--origin", default="user", type=click.Choice(["user", "external", "inferred"]))
@click.option("--source-id", default="cli")
@click.option("--confirm", is_flag=True, help="Confirm external/suspicious writes")
def todo_create(
    title: str,
    details: str,
    status: str,
    due_date: str,
    origin: str,
    source_id: str,
    confirm: bool,
) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "todo.create",
        {
            "title": title,
            "details": details,
            "status": status,
            "due_date": due_date,
            "origin": origin,
            "source_id": source_id,
            "user_confirmed": confirm,
        },
        response_model=MemoryWriteResult,
    )
    click.echo(_dump_model(result))


@todo.command("list")
@click.option("--limit", default=100, help="Maximum entries")
def todo_list(limit: int) -> None:
    config = _get_config()
    result = rpc_call(config, "todo.list", {"limit": limit}, response_model=TodoListResult)
    for item in result.entries:
        value = item.get("value", {})
        if isinstance(value, dict):
            title = str(value.get("title", ""))
            status = str(value.get("status", ""))
        else:
            title = ""
            status = ""
        click.echo(f"{item.get('id', '')} {status} {title}")


@todo.command("get")
@click.argument("entry_id")
def todo_get(entry_id: str) -> None:
    config = _get_config()
    result = rpc_call(config, "todo.get", {"entry_id": entry_id}, response_model=TodoGetResult)
    click.echo(_dump_model(result))


@todo.command("delete")
@click.argument("entry_id")
def todo_delete(entry_id: str) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "todo.delete",
        {"entry_id": entry_id},
        response_model=TodoDeleteResult,
    )
    click.echo(_dump_model(result))


@todo.command("verify")
@click.argument("entry_id")
def todo_verify(entry_id: str) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "todo.verify",
        {"entry_id": entry_id},
        response_model=TodoVerifyResult,
    )
    click.echo(_dump_model(result))


@todo.command("export")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "csv"]))
def todo_export(fmt: str) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "todo.export",
        {"format": fmt},
        response_model=TodoExportResult,
    )
    click.echo(str(result.data))


@cli.group()
def web() -> None:
    """Web search/fetch operations."""


@web.command("search")
@click.argument("query")
@click.option("--limit", default=5, help="Maximum results")
def web_search(query: str, limit: int) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "web.search",
        {"query": query, "limit": limit},
        response_model=WebSearchResult,
    )
    click.echo(_dump_model(result))


@web.command("fetch")
@click.argument("url")
@click.option("--snapshot", is_flag=True, help="Persist a fetched-text snapshot under data_dir.")
def web_fetch(url: str, snapshot: bool) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "web.fetch",
        {"url": url, "snapshot": snapshot},
        response_model=WebFetchResult,
    )
    click.echo(_dump_model(result))


@cli.group("realitycheck")
def realitycheck_group() -> None:
    """Reality Check scoped search/read operations."""


@realitycheck_group.command("search")
@click.argument("query")
@click.option("--limit", default=5, help="Maximum results")
@click.option("--mode", default="auto", type=click.Choice(["auto", "local", "remote"]))
def realitycheck_search(query: str, limit: int, mode: str) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "realitycheck.search",
        {"query": query, "limit": limit, "mode": mode},
        response_model=RealityCheckSearchResult,
    )
    click.echo(_dump_model(result))


@realitycheck_group.command("read")
@click.argument("path")
@click.option("--max-bytes", default=131072)
def realitycheck_read(path: str, max_bytes: int) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "realitycheck.read",
        {"path": path, "max_bytes": max_bytes},
        response_model=RealityCheckReadResult,
    )
    click.echo(_dump_model(result))


@cli.group("fs")
def fs_group() -> None:
    """Filesystem read-first operations."""


@fs_group.command("list")
@click.argument("path", required=False, default=".")
@click.option("--recursive", is_flag=True)
@click.option("--limit", default=200)
def fs_list(path: str, recursive: bool, limit: int) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "fs.list",
        {"path": path, "recursive": recursive, "limit": limit},
        response_model=FsListResult,
    )
    click.echo(_dump_model(result))


@fs_group.command("read")
@click.argument("path")
@click.option("--max-bytes", default=65536)
def fs_read(path: str, max_bytes: int) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "fs.read",
        {"path": path, "max_bytes": max_bytes},
        response_model=FsReadResult,
    )
    click.echo(_dump_model(result))


@fs_group.command("write")
@click.argument("path")
@click.option("--content", required=True)
@click.option("--confirm", is_flag=True, help="Explicitly confirm write side effects.")
def fs_write(path: str, content: str, confirm: bool) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "fs.write",
        {"path": path, "content": content, "confirm": confirm},
        response_model=FsWriteResult,
    )
    click.echo(_dump_model(result))


@cli.group("git")
def git_group() -> None:
    """Git read-only workflow helpers."""


@git_group.command("status")
@click.option("--repo", "repo_path", default=".")
def git_status(repo_path: str) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "git.status",
        {"repo_path": repo_path},
        response_model=GitStatusResult,
    )
    click.echo(_dump_model(result))


@git_group.command("diff")
@click.option("--repo", "repo_path", default=".")
@click.option("--ref", default="")
@click.option("--max-lines", default=400)
def git_diff(repo_path: str, ref: str, max_lines: int) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "git.diff",
        {"repo_path": repo_path, "ref": ref, "max_lines": max_lines},
        response_model=GitDiffResult,
    )
    click.echo(_dump_model(result))


@git_group.command("log")
@click.option("--repo", "repo_path", default=".")
@click.option("--limit", default=20)
def git_log(repo_path: str, limit: int) -> None:
    config = _get_config()
    result = rpc_call(
        config,
        "git.log",
        {"repo_path": repo_path, "limit": limit},
        response_model=GitLogResult,
    )
    click.echo(_dump_model(result))


@cli.group()
def task() -> None:
    """Scheduler task operations."""


@task.command("list")
def task_list() -> None:
    config = _get_config()
    result = rpc_call(config, "task.list", response_model=TaskListResult)
    for item in result.tasks:
        click.echo(f"{item.id} {item.name} enabled={item.enabled}")


@cli.group()
def skill() -> None:
    """Skill profiling and lock workflow."""


@skill.command("list")
def skill_list() -> None:
    """List installed skills tracked by the daemon inventory."""
    config = _get_config()
    result = rpc_call(config, "skill.list", response_model=SkillListResult)
    if not result.skills:
        _echo("No installed skills", fg="yellow")
        return
    for item in result.skills:
        click.echo(f"{item.name}@{item.version} state={item.state} author={item.author}")


@skill.command("review")
@click.argument("skill_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def skill_review(skill_path: Path) -> None:
    """Run daemon-backed skill review and show findings/reputation."""
    config = _get_config()
    result = rpc_call(
        config,
        "skill.review",
        {"skill_path": str(skill_path)},
        response_model=SkillReviewResult,
    )
    click.echo(_dump_model(result))


@skill.command("install")
@click.argument("skill_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--approve-untrusted", is_flag=True, help="Approve untrusted signature state.")
def skill_install(skill_path: Path, approve_untrusted: bool) -> None:
    """Install a reviewed skill through daemon policy gates."""
    config = _get_config()
    result = rpc_call(
        config,
        "skill.install",
        {"skill_path": str(skill_path), "approve_untrusted": approve_untrusted},
        response_model=SkillInstallResult,
    )
    click.echo(_dump_model(result))


@skill.command("revoke")
@click.argument("skill_name")
@click.option("--reason", default="security_revoke", help="Revocation reason")
def skill_revoke(skill_name: str, reason: str) -> None:
    """Revoke an installed skill (state transition to revoked)."""
    config = _get_config()
    result = rpc_call(
        config,
        "skill.revoke",
        {"skill_name": skill_name, "reason": reason},
        response_model=SkillRevokeResult,
    )
    click.echo(_dump_model(result))


@skill.command("profile")
@click.argument("skill_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--duration", default="1h", help="Profile duration hint (metadata only)")
def skill_profile(skill_path: Path, duration: str) -> None:
    """Run skill static profile and save capability profile."""
    from shisad.skills import CapabilityInferenceAnalyzer, SkillProfiler, load_skill_bundle

    bundle = load_skill_bundle(skill_path)
    inferred = CapabilityInferenceAnalyzer().infer(bundle)
    profiler = SkillProfiler()
    for host in inferred.network_domains:
        profiler.record_network(host)
    for path in inferred.file_paths:
        profiler.record_filesystem(path)
    for command in inferred.shell_commands:
        profiler.record_shell(command)
    for env_name in inferred.environment_vars:
        profiler.record_environment(env_name)

    out_path = skill_path / ".shisad-profile.json"
    profiler.save(out_path)
    click.echo(f"Profile captured ({duration}) -> {out_path}")


@skill.command("generate-manifest")
@click.argument("skill_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--from-profile", "from_profile", is_flag=True, default=False)
@click.option("--author", default="local-user")
@click.option("--source-repo", default="local")
def skill_generate_manifest(
    skill_path: Path,
    from_profile: bool,
    author: str,
    source_repo: str,
) -> None:
    """Generate skill.manifest.yaml from profile output."""
    from shisad.skills import SkillProfiler, generate_manifest_from_profile

    if not from_profile:
        raise click.ClickException("--from-profile is required for this command")
    profile_path = skill_path / ".shisad-profile.json"
    profiler = SkillProfiler.load(profile_path)
    manifest = generate_manifest_from_profile(
        profile=profiler.profile,
        name=skill_path.name,
        author=author,
        source_repo=source_repo,
        version="1.0.0",
    )
    payload = manifest.model_dump(mode="json")
    payload["signature"] = f"sha256:{manifest.manifest_hash()}"
    out_path = skill_path / "skill.manifest.yaml"
    out_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    click.echo(f"Generated manifest -> {out_path}")


@skill.command("lock")
@click.argument("skill_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
def skill_lock(skill_path: Path) -> None:
    """Lock skill to manifest hash."""
    from shisad.skills import lock_skill_manifest, parse_manifest

    manifest_path = skill_path / "skill.manifest.yaml"
    manifest = parse_manifest(manifest_path)
    lock_path = skill_path / ".shisad-skill.lock"
    digest = lock_skill_manifest(manifest, lock_path)
    click.echo(f"Locked {manifest.name}@{manifest.version} -> {digest[:16]}…")


@cli.group()
def policy() -> None:
    """Policy compiler and explanation helpers."""


@policy.command("explain")
@click.option("--session", "session_id", default="", help="Session ID")
@click.option("--action", default="", help="Action to explain")
@click.option("--tool", "tool_name", default="", help="Tool name")
def policy_explain(session_id: str, action: str, tool_name: str) -> None:
    """Explain effective policy inheritance for a session/action."""
    config = _get_config()
    result = rpc_call(
        config,
        "policy.explain",
        {"session_id": session_id or None, "action": action, "tool_name": tool_name or None},
        response_model=PolicyExplainResult,
    )
    click.echo(_dump_model(result))


if __name__ == "__main__":
    cli()
