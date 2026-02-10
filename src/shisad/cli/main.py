"""shisad CLI entry point.

Click-based CLI that connects to the daemon via the control API (Unix socket).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
import yaml

from shisad.core.config import DaemonConfig


def _get_config() -> DaemonConfig:
    return DaemonConfig()


@click.group()
@click.version_option()
def cli() -> None:
    """shisad — Security-first AI agent daemon."""


# --- Daemon lifecycle ---


@cli.command()
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (don't daemonize)")
def start(foreground: bool) -> None:
    """Start the shisad daemon."""
    config = _get_config()

    if not foreground:
        click.echo(f"Starting shisad daemon (socket: {config.socket_path})")
        # Full daemonization is a future enhancement; for now, run in foreground
        click.echo("Note: --foreground is currently the only supported mode")

    click.echo(f"Data directory: {config.data_dir}")
    click.echo(f"Control socket: {config.socket_path}")

    from shisad.daemon.runner import run_daemon

    try:
        asyncio.run(run_daemon(config))
    except KeyboardInterrupt:
        click.echo("\nShutting down...")


@cli.command()
def stop() -> None:
    """Stop the shisad daemon."""
    config = _get_config()

    if not config.socket_path.exists():
        click.echo("Daemon does not appear to be running (no socket found)")
        sys.exit(1)

    async def _stop() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            await client.call("daemon.shutdown")
            click.echo("Shutdown signal sent")
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        finally:
            await client.close()

    asyncio.run(_stop())


@cli.command()
def status() -> None:
    """Show daemon status."""
    config = _get_config()

    if not config.socket_path.exists():
        click.echo("Status: not running")
        sys.exit(1)

    async def _status() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            result = await client.call("daemon.status")
            click.echo("Status: running")
            click.echo(json.dumps(result, indent=2))
        except Exception as e:
            click.echo(f"Status: error ({e})")
            sys.exit(1)
        finally:
            await client.close()

    asyncio.run(_status())


# --- Session commands ---


@cli.group()
def session() -> None:
    """Manage sessions."""


@session.command("create")
@click.option("--user", "-u", default="", help="User ID")
@click.option("--workspace", "-w", default="", help="Workspace ID")
def session_create(user: str, workspace: str) -> None:
    """Create a new session."""
    config = _get_config()

    async def _create() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            result = await client.call(
                "session.create", {"user_id": user, "workspace_id": workspace}
            )
            click.echo(f"Session created: {result['session_id']}")
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        finally:
            await client.close()

    asyncio.run(_create())


@session.command("message")
@click.argument("session_id")
@click.argument("content")
def session_message(session_id: str, content: str) -> None:
    """Send a message to a session."""
    config = _get_config()

    async def _message() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            result = await client.call(
                "session.message", {"session_id": session_id, "content": content}
            )
            click.echo(result.get("response", ""))
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        finally:
            await client.close()

    asyncio.run(_message())


@session.command("list")
def session_list() -> None:
    """List active sessions."""
    config = _get_config()

    async def _list() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            result = await client.call("session.list")
            sessions = result.get("sessions", [])
            if not sessions:
                click.echo("No active sessions")
            else:
                for s in sessions:
                    click.echo(f"  {s['id']}  state={s['state']}  user={s.get('user_id', '')}")
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        finally:
            await client.close()

    asyncio.run(_list())


@session.command("restore")
@click.argument("checkpoint_id")
def session_restore(checkpoint_id: str) -> None:
    """Restore a session from a checkpoint ID."""
    config = _get_config()

    async def _restore() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            result = await client.call("session.restore", {"checkpoint_id": checkpoint_id})
            if result.get("restored"):
                click.echo(
                    f"Restored session {result.get('session_id')} from checkpoint {checkpoint_id}"
                )
            else:
                click.echo(f"Checkpoint not found: {checkpoint_id}", err=True)
                sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        finally:
            await client.close()

    asyncio.run(_restore())


@session.command("rollback")
@click.argument("checkpoint_id")
def session_rollback(checkpoint_id: str) -> None:
    """Rollback a session to a checkpoint ID."""
    config = _get_config()

    async def _rollback() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            result = await client.call("session.rollback", {"checkpoint_id": checkpoint_id})
            if result.get("rolled_back"):
                click.echo(
                    f"Rolled back session {result.get('session_id')} to checkpoint {checkpoint_id}"
                )
            else:
                click.echo(f"Checkpoint not found: {checkpoint_id}", err=True)
                sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        finally:
            await client.close()

    asyncio.run(_rollback())


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

    async def _subscribe() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        received = 0
        try:
            await client.connect()
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
        except KeyboardInterrupt:
            return
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        finally:
            await client.close()

    asyncio.run(_subscribe())


@cli.group()
def memory() -> None:
    """Memory manager operations."""


@memory.command("list")
@click.option("--limit", default=100, help="Maximum entries")
def memory_list(limit: int) -> None:
    config = _get_config()

    async def _list() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            result = await client.call("memory.list", {"limit": limit})
            for item in result.get("entries", []):
                click.echo(f"{item['id']} {item['entry_type']} {item['key']}")
        finally:
            await client.close()

    asyncio.run(_list())


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

    async def _write() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            result = await client.call(
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
            )
            click.echo(json.dumps(result, indent=2))
        finally:
            await client.close()

    asyncio.run(_write())


@cli.group()
def task() -> None:
    """Scheduler task operations."""


@task.command("list")
def task_list() -> None:
    config = _get_config()

    async def _list() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            result = await client.call("task.list")
            for item in result.get("tasks", []):
                click.echo(f"{item['id']} {item['name']} enabled={item['enabled']}")
        finally:
            await client.close()

    asyncio.run(_list())


@cli.group()
def skill() -> None:
    """Skill profiling and lock workflow."""


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

    async def _explain() -> None:
        from shisad.core.api.transport import ControlClient

        client = ControlClient(config.socket_path)
        try:
            await client.connect()
            result = await client.call(
                "policy.explain",
                {
                    "session_id": session_id or None,
                    "action": action,
                    "tool_name": tool_name or None,
                },
            )
            click.echo(json.dumps(result, indent=2))
        finally:
            await client.close()

    asyncio.run(_explain())


if __name__ == "__main__":
    cli()
