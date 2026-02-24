"""shisad CLI entry point.

Click-based CLI that connects to the daemon via the control API (Unix socket).
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from collections.abc import Callable, Coroutine
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

import click
import yaml
from click.shell_completion import get_completion_class
from pydantic import BaseModel

from shisad.cli.rpc import rpc_call, rpc_run, run_async
from shisad.core.api.schema import (
    ActionConfirmResult,
    ActionPendingResult,
    ActionRejectResult,
    ChannelPairingProposalResult,
    ConfirmationMetricsResult,
    DaemonShutdownResult,
    DaemonStatusResult,
    DashboardMarkFalsePositiveResult,
    DashboardQueryResult,
    DoctorCheckResult,
    FsListResult,
    FsReadResult,
    FsWriteResult,
    GitDiffResult,
    GitLogResult,
    GitStatusResult,
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
    SessionGrantCapabilitiesResult,
    SessionListResult,
    SessionMessageResult,
    SessionRestoreResult,
    SessionRollbackResult,
    SessionSetModeResult,
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
    WebFetchResult,
    WebSearchResult,
)
from shisad.core.config import DaemonConfig


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


def _dump_model(model: BaseModel) -> str:
    return json.dumps(model.model_dump(mode="json", exclude_unset=True), indent=2)


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
def chat(session_id: str, user: str, workspace: str) -> None:
    """Interactive chat with the shisad daemon."""
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


def _run_daemon_with_autoreload_sync(config: DaemonConfig) -> None:
    run_async(_run_daemon_with_autoreload(config=config))


def _run_daemon_foreground(config: DaemonConfig) -> None:
    from shisad.daemon.runner import run_daemon

    run_async(run_daemon(config))


@cli.command()
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (don't daemonize)")
@click.option(
    "--debug",
    is_flag=True,
    help="Run in foreground with DEBUG logging and local autoreload.",
)
def start(foreground: bool, debug: bool) -> None:
    """Start the shisad daemon."""
    config = _get_config()
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
    help="Component to check (all, dependencies, policy, channels, sandbox, realitycheck)",
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
    click.echo(result.response)


@session.command("list")
def session_list() -> None:
    """List active sessions."""
    config = _get_config()

    result = rpc_call(config, "session.list", response_model=SessionListResult)
    if not result.sessions:
        click.echo("No active sessions")
        return
    for item in result.sessions:
        click.echo(
            f"  {item.id}  state={item.state}  mode={item.mode}  user={item.user_id}"
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
    click.echo(f"Checkpoint not found: {checkpoint_id}", err=True)
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
    click.echo(f"Checkpoint not found: {checkpoint_id}", err=True)
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
        nonce_value = (row.decision_nonce or "").strip()
        click.echo(
            f"{row.confirmation_id} nonce={nonce_value} status={row.status} "
            f"tool={row.tool_name} reason={row.reason}"
        )
        preview = (row.safe_preview or "").strip()
        if preview:
            click.echo(preview)
            click.echo("")


def _resolve_pending_decision_nonce(
    *,
    config: DaemonConfig,
    confirmation_id: str,
) -> str:
    for limit in (200, 1000, 5000, 20000):
        pending = rpc_call(
            config,
            "action.pending",
            {"status": "pending", "limit": limit, "include_ui": False},
            response_model=ActionPendingResult,
        )
        for row in pending.actions:
            if row.confirmation_id != confirmation_id:
                continue
            return (row.decision_nonce or "").strip()
    return ""


@action.command("confirm")
@click.argument("confirmation_id")
@click.option("--nonce", default="", help="Decision nonce for replay-safe confirmation")
@click.option("--reason", default="", help="Operator note")
def action_confirm(confirmation_id: str, nonce: str, reason: str) -> None:
    """Approve one pending confirmation."""
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
        "action.confirm",
        {
            "confirmation_id": confirmation_id,
            "decision_nonce": decision_nonce,
            "reason": reason,
        },
        response_model=ActionConfirmResult,
    )
    click.echo(_dump_model(result))


@action.command("reject")
@click.argument("confirmation_id")
@click.option("--reason", default="manual_reject", help="Rejection reason")
def action_reject(confirmation_id: str, reason: str) -> None:
    """Reject one pending confirmation."""
    config = _get_config()
    result = rpc_call(
        config,
        "action.reject",
        {"confirmation_id": confirmation_id, "reason": reason},
        response_model=ActionRejectResult,
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
            f"{event.timestamp} {event.event_type} "
            f"session={event.session_id} actor={event.actor}"
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
            f"{event.timestamp} host={event.data.get('destination_host','')} "
            f"allowed={event.data.get('allowed')} reason={event.data.get('reason','')}"
        )


@dashboard.command("skill-provenance")
@click.option("--limit", default=100, help="Maximum rows")
def dashboard_skill_provenance(limit: int) -> None:
    """View skill installation/review/profile/revocation timeline."""
    config = _get_config()
    result = rpc_call(
        config,
        "dashboard.skill_provenance",
        {"limit": limit},
        response_model=DashboardQueryResult,
    )
    for row in result.timeline:
        click.echo(f"{row.skill_name} versions={','.join(row.versions)}")


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
