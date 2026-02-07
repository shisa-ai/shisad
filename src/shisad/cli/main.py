"""shisad CLI entry point.

Click-based CLI that connects to the daemon via the control API (Unix socket).
"""

from __future__ import annotations

import asyncio
import json
import sys

import click

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


# --- Audit commands ---


@cli.group()
def audit() -> None:
    """Query the audit log."""


@audit.command("query")
@click.option("--since", help="Show events since (e.g., '1h', '2025-01-01')")
@click.option("--type", "event_type", help="Filter by event type")
@click.option("--session", "session_id", help="Filter by session ID")
@click.option("--limit", default=100, help="Maximum results")
def audit_query(
    since: str | None,
    event_type: str | None,
    session_id: str | None,
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
    # For now, pass through simple filters (time parsing is a future enhancement)
    results = log.query(event_type=event_type, session_id=session_id, limit=limit)

    if not results:
        click.echo("No matching events")
        return

    for entry in results:
        ts = entry.get("timestamp", "")
        et = entry.get("event_type", "")
        sid = entry.get("session_id", "—")
        click.echo(f"  {ts}  {et:20s}  session={sid}")


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


if __name__ == "__main__":
    cli()
