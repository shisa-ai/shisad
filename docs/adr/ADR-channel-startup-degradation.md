# ADR: Channel Startup Timeouts and Degraded Status

*Status: Accepted and shipped in v0.8.2*
*Date: 2026-07-30*
*Issue: [#111](https://github.com/shisa-ai/shisad/issues/111)*

## Context

`DaemonServices.build()` owns the data-root lock while it constructs the
configured Matrix, Discord, Telegram, and Slack channels. The daemon does not
start its control socket until construction returns. A connector whose
`connect()` coroutine never returns can therefore leave a live process holding
the lock without a control surface through which the user can inspect or stop
it.

Telegram currently performs application initialization, application start,
and polling startup inline. Matrix, Discord, and Slack currently schedule their
long-running network loops, but their daemon builders still call `connect()`
without a timeout.

Optional integration failure is not a reason to disable unrelated assistant
functionality. The daemon must either isolate the failed connector and report
its degraded state, or fail promptly when it cannot clean up safely.

## Decision

1. `DaemonConfig` exposes one validated
   `channel_startup_timeout_seconds` setting. It defaults to 15 seconds and has
   a minimum of 0.1 seconds.
2. The daemon owns the timeout around every enabled Matrix, Discord, Telegram,
   and Slack `connect()` call.
3. A connector timeout or ordinary connector exception triggers time-limited
   disconnect cleanup. When cleanup succeeds:
   - the connector is excluded from active ingress and delivery routing;
   - the core daemon and unrelated connectors continue starting;
   - daemon status reports the connector as enabled, disconnected, and
     startup-degraded with a stable reason code.
4. When cleanup cannot complete within the same bound, startup fails with a
   redacted error. The existing outer construction boundary releases the
   data-root lock.
   Each built-in adapter exposes a strict failed-start disconnect path that
   surfaces transport cleanup failure and retains its resource reference until
   cleanup succeeds. Ordinary shutdown keeps its existing best-effort behavior.
5. Startup warnings contain the connector name, stable reason code, timeout
   where relevant, and exception type where relevant. They do not contain the
   exception message, configured credential, or endpoint.
6. A healthy connector remains in the active channel map and follows its
   existing ingress, delivery, status, and shutdown paths.
7. Required-field validation remains deterministic and fail-fast. This ADR
   changes runtime connection failure, not the meaning of an explicitly
   enabled but structurally incomplete configuration.

## Status Output

Each channel's existing `enabled`, `available`, and `connected` fields remain.
Daemon status adds a nested `startup` object:

```json
{
  "status": "degraded",
  "reason_code": "channel.startup_timeout",
  "timeout_seconds": 15.0
}
```

A successful enabled connector reports `status: "ready"` with an empty reason
code. A disabled connector reports `status: "disabled"`. Connector exceptions
use `channel.startup_error` plus an `error_type`; exception text is not
included in public status output.

## Invariants

- A configured connector cannot prevent the control socket from appearing
  indefinitely when its async lifecycle honors cancellation.
- A degraded connector cannot receive channel traffic or accept delivery
  attempts through the active channel map.
- Failed-start cleanup finishes before the daemon continues in a degraded
  state.
- Cancellation of daemon construction still propagates rather than being
  converted into connector degradation.
- No credential or endpoint is added to startup logs or daemon status.
- No custom transaction or locking protocol is introduced.

## Non-Goals

- Concurrent connector construction.
- A general connector reconnection supervisor.
- Redesigning long-running Discord, Matrix, or Slack background task health.
- Changing static required-field validation.
- Broad extraction of `DaemonServices.build()` or general shutdown hardening.
- Guaranteeing recovery from connector code that blocks the event-loop thread
  or deliberately suppresses task cancellation.

## Implementation

```text
docs/
├── ENV-VARS.md
├── ROADMAP.md
└── adr/ADR-channel-startup-degradation.md
src/shisad/
├── channels/
│   ├── discord.py
│   ├── matrix.py
│   ├── slack.py
│   └── telegram.py
├── core/config.py
└── daemon/
    ├── handlers/_impl_admin.py
    └── services.py
tests/
├── integration/test_daemon_data_lock.py
└── unit/
    ├── test_channels.py
    ├── test_config_env.py
    └── test_daemon_services.py
```

## Verification

The representative daemon journey:

1. Enable Telegram with structurally valid placeholder configuration.
2. Replace its connection coroutine with one that waits forever but honors
   cancellation.
3. Confirm the timeout cancels and disconnects the connector.
4. Confirm the control socket starts and `daemon.status` reports Telegram as
   degraded with `channel.startup_timeout`.
5. Confirm a core status call succeeds and shutdown releases the data-root
   lock.

Focused unit evidence also covers:

- all four builders passing through the common startup-timeout path;
- a healthy connector remaining active;
- connector exceptions degrading without logging their messages;
- every built-in adapter surfacing strict failed-start transport cleanup
  failure without discarding its resource reference;
- Telegram initialization failure and pre-polling timeout respecting
  application/updater running state while still completing shutdown;
- failed cleanup causing startup failure rather than unsafe degraded
  continuation;
- config default, environment override, and lower-bound validation; and
- Telegram transport initialization errors reaching the daemon boundary.

The first-principles behavioral tests cover the shared daemon startup change.
A live external-provider run is not needed for this deterministic
fault-injection fix.
