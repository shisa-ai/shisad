"""Optional API-first web snapshot renderer for dashboard/confirmation views."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from shisad.core.api.transport import ControlClient


async def fetch_web_snapshot(socket_path: Path) -> dict[str, Any]:
    """Fetch web-view data from control API."""
    client = ControlClient(socket_path)
    try:
        await client.connect()
        sessions = await client.call("session.list")
        pending = await client.call("action.pending", {"status": "pending", "limit": 100})
        alerts = await client.call("dashboard.alerts", {"limit": 100})
        egress = await client.call("dashboard.egress_review", {"limit": 100})
    finally:
        await client.close()
    return {
        "sessions": sessions.get("sessions", []),
        "pending_actions": pending.get("actions", []),
        "alerts": alerts.get("alerts", []),
        "egress_events": egress.get("events", []),
    }


def render_web_snapshot(snapshot: dict[str, Any]) -> str:
    """Render static HTML using snapshot data from control API."""
    payload = html.escape(json.dumps(snapshot, indent=2, sort_keys=True))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>shisad security dashboard</title>
  <style>
    :root {{
      --bg: #f4f7fb;
      --panel: #ffffff;
      --ink: #173145;
      --muted: #557083;
      --accent: #0b8f6b;
      --warn: #af5f00;
      --border: #c8d8e4;
    }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, -apple-system, "Segoe UI", sans-serif;
      background: radial-gradient(circle at 80% 0%, #d7eef8 0, #f4f7fb 42%);
      color: var(--ink);
    }}
    header {{
      padding: 20px 28px 8px;
    }}
    h1 {{
      margin: 0;
      font-size: 1.4rem;
      letter-spacing: 0.03em;
      text-transform: uppercase;
    }}
    main {{
      display: grid;
      gap: 12px;
      padding: 12px 28px 28px;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      box-shadow: 0 6px 20px rgb(12 47 69 / 8%);
    }}
    section h2 {{
      margin: 0 0 6px;
      font-size: 0.95rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      font-size: 0.8rem;
      line-height: 1.4;
      max-height: 420px;
      overflow: auto;
    }}
    .note {{
      padding: 0 28px 20px;
      color: var(--warn);
      font-size: 0.85rem;
    }}
  </style>
</head>
<body>
  <header>
    <h1>shisad API-first dashboard snapshot</h1>
  </header>
  <main>
    <section><h2>Sessions</h2><pre id="sessions"></pre></section>
    <section><h2>Pending confirmations</h2><pre id="pending"></pre></section>
    <section><h2>Alerts</h2><pre id="alerts"></pre></section>
    <section><h2>Egress events</h2><pre id="egress"></pre></section>
  </main>
  <div class="note">
    Static snapshot for investigation/export. Live actions still run through control API.
  </div>
  <script>
    const snapshot = JSON.parse(`{payload}`);
    document.getElementById("sessions").textContent =
      JSON.stringify(snapshot.sessions, null, 2);
    document.getElementById("pending").textContent =
      JSON.stringify(snapshot.pending_actions, null, 2);
    document.getElementById("alerts").textContent =
      JSON.stringify(snapshot.alerts, null, 2);
    document.getElementById("egress").textContent =
      JSON.stringify(snapshot.egress_events, null, 2);
  </script>
</body>
</html>
"""


async def write_web_snapshot(*, socket_path: Path, output_path: Path) -> Path:
    """Fetch current API data and write a static dashboard HTML snapshot."""
    snapshot = await fetch_web_snapshot(socket_path)
    html_payload = render_web_snapshot(snapshot)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_payload, encoding="utf-8")
    return output_path
