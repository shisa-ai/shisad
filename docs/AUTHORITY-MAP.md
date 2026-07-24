# Runtime Authority Map

This document records selected live authority and ownership boundaries in the
v0.8.1 development tree after the handler-graph and typed-RPC-registry
consolidations. It is not a claim that every route already has one ideal owner.

## Reading the map

- **Ingress authority** authenticates or scopes the caller before work enters
  a session.
- **Decision authority** decides whether a proposed effect may execute.
- **Lifecycle authority** owns durable state transitions and restart behavior.
- **Effect authority** invokes the concrete toolkit, adapter, or executor.
- **Delivery authority** binds a result to its intended surface and target.

The shared planner / `tool.execute` path and authenticated operator convenience
RPCs are distinct today. The latter are not model-callable planner tools and do
not claim the shared PEP/control-plane/audit pipeline.

## Composition owners

| Concern | Current owner | Important consumers / boundary |
|---|---|---|
| Runtime service graph | [`DaemonServices.build`](../src/shisad/daemon/services.py) | Builds stores, policy/PEP/control-plane clients, adapters, executors, scheduler, channel registry, and one service-owned control-handler graph |
| Live daemon surface | [`_serve_daemon`](../src/shisad/daemon/runner.py) | Consumes the service-owned graph, registers local RPC descriptors, and starts approval-web callbacks, channel receive pumps, scheduler delivery, and recovery |
| Typed handler graph | [`DaemonControlHandlers`](../src/shisad/daemon/control_handlers.py) | Owns the single mutable implementation plus ten explicit typed domain-handler groups used by RPC binding and live ingress |
| Mutable handler implementation | [`HandlerImplementation`](../src/shisad/daemon/handlers/_impl.py) | Loads pending actions, binds approval-web callbacks, and composes confirmation, session, tool, channel, scheduler, and assistant behavior |
| Typed control API models | [`core/api/schema.py`](../src/shisad/core/api/schema.py) | Request/response validation for the local RPC surface |
| Control RPC descriptors | [`core/api/rpc_registry.py`](../src/shisad/core/api/rpc_registry.py) | Immutable method name, params/result models, admin posture, grouped route, readiness, and production/test availability projected into runner registration and machine introspection |

`DaemonServices.build()` constructs one `DaemonControlHandlers`. Local RPC
registration binds descriptors against its grouped owners; signed A2A ingress
binds the `session` group; channel receive pumps bind the `admin` group.
Scheduler, recovery, delivery, and approval-web callbacks retain the same
underlying `HandlerImplementation`.

## Route and enforcement map

| Route family | Ingress authority | Decision / effect path | Delivery and observability |
|---|---|---|---|
| Local `session.message` | Authenticated Unix control RPC and session principal/workspace binding | Session handler → planner → registered shared tool execution → policy/PEP/control plane → confirmation or executor | Session response plus shared audit/action events |
| Discord, Slack, Telegram, Matrix message | Connector identity allowlist and concrete workspace/channel/thread binding | [`channel_receive_pump`](../src/shisad/daemon/event_wiring.py) → channel ingest → same session/planner path | Exact connector/workspace/target binding; durable delivery attempts and scoped fallback |
| Signed A2A session message | Public-key fingerprint, signature/replay checks, allowed-intent grant, and per-peer limits | A2A listener → service-time handler → same session/planner path under the remote principal's grants | A2A ingress-evaluation event plus shared-path response/audit |
| Administrative `tool.execute` | Authenticated local admin RPC with typed params | Shared tool-execution handler → policy/PEP/control plane → confirmation or executor | Shared action/execution audit path |
| Convenience `web.*` / `realitycheck.*` | Authenticated local operator RPC and typed params | [`_impl_assistant.py`](../src/shisad/daemon/handlers/_impl_assistant.py) → toolkit-local URL/configuration/result checks | RPC result and `operator_bypass_rpc` process log; no shared PEP/audit equivalence claim |
| Convenience `email.*` | Authenticated local operator RPC and typed params | Assistant handler → configured local MsgVault toolkit with account/id constraints | RPC result and bypass log; MsgVault remains provider-sync authority |
| Convenience `fs.*` / `git.*` | Authenticated local operator RPC, configured roots, managed/control-file exclusions, and bounded Git environment | Assistant handler → filesystem/Git toolkit | RPC result and bypass log; route-local path/Git protections apply |
| `action.confirm` / `action.reject` | Admin RPC, trusted channel control command, or method-specific approval surface | Exact confirmation/action/nonce, actor/surface, proof, policy, and durable attempt checks → shared effect execution or terminal rejection | Decision, attempt, result, and delivery correlation remain durable across restart |
| Scheduler run | Persisted task, capability snapshot, scheduler accounting, and due-state checks | Scheduler → shared handler/tool path; a risky action may become pending | Delivery uses the stored channel binding; uncertain effect/delivery disables or contains work |
| Approval web | Capability link plus WebAuthn ceremony and origin checks | Bound callback into the active handler's pending-action decision path | Browser is WebAuthn-only; it is not a TOTP entry surface |

## Pending-action lifecycle

| State concern | Current authority |
|---|---|
| Public state projection | [`ActionStateView`](../src/shisad/core/action_state.py) |
| Mutable pending row | `PendingAction` in [`_impl.py`](../src/shisad/daemon/handlers/_impl.py) |
| Queue/create/persist/load/recovery | Handler implementation methods in `_impl.py` |
| Confirm/reject/proof verification | [`_impl_confirmation.py`](../src/shisad/daemon/handlers/_impl_confirmation.py) |
| Planner/session evaluation and amendment correlation | [`_impl_session.py`](../src/shisad/daemon/handlers/_impl_session.py) |
| Durable effect identity | Confirmation id, action digest, decision nonce, approval-evidence hash, attempt id, result id, and provider idempotency metadata |
| Restart rule | Only documented trusted retry descriptors may receive one bounded recovery; target-bearing, drifted, corrupt, contradictory, or otherwise ambiguous attempts become `outcome_unknown` |

Four network channel adapters currently retain **no provider exactly-once or
idempotency guarantee**. Their delivery ledger prevents silent local replay and
preserves reconciliation evidence; it does not upgrade a provider's contract.

## RPC descriptor boundary

[`core/api/rpc_registry.py`](../src/shisad/core/api/rpc_registry.py) owns one
explicit immutable descriptor for each of 122 production methods plus the
test-only reset method. Runner registration and machine introspection consume
that same projection. Each descriptor binds through a closed group map to one
of the ten typed owners held by `DaemonControlHandlers`; there is no parallel
RPC-shaped forwarding facade. `core/api/schema.py` remains the typed
request/result-model authority, and the planner tool registry remains a
separate consumer with a different contract.

## Intent, secret, and URL boundaries

| Concern | Current authorities | Current non-claim |
|---|---|---|
| Explicit memory intent | Planner/session orchestration plus bounded daemon-side proposal builders in [`_impl_session.py`](../src/shisad/daemon/handlers/_impl_session.py) | The daemon still performs some prose interpretation; it is not yet purely structured planner output |
| Ingress secret detection | [`security/firewall/secrets.py`](../src/shisad/security/firewall/secrets.py) and ingress taint consumers | Pattern coverage is not yet one canonical registry across every consumer |
| Output secret handling | [`security/firewall/output.py`](../src/shisad/security/firewall/output.py) | Output redaction rules are not asserted identical to ingress or PEP DLP rules |
| PEP argument DLP | [`security/pep.py`](../src/shisad/security/pep.py) | PEP argument checks are route-scoped and do not describe operator convenience RPCs |
| URL syntax parsing | [`core/url_parsing.py`](../src/shisad/core/url_parsing.py) | Syntax normalization alone is not a complete SSRF/network authorization decision |
| URL/network policy consumers | Provider base URLs, executor proxy, browser, web/reality-check toolkits, PEP, output firewall, approval origin, and A2A transports | Private-address, allowlist, redirect, DNS, and connect-path semantics are not yet derived from one canonical primitive |

## Bounded consolidation sequence

The consolidation sequence is intentionally sequential so each step preserves
a characterized user journey:

1. Establish one live handler/composition owner. *(Implemented in the current
   tree.)*
2. Establish one pending-action lifecycle owner. *(Implemented in the current
   tree.)*
3. Generate RPC registration and introspection from typed descriptors, then
   remove the redundant forwarding facade. *(Implemented in the current
   tree.)*
4. Give direct operator RPCs one explicit enforcement and audit contract while
   preserving their authenticated functionality.
5. Replace daemon prose intent interpretation with structured planner-produced
   intent.
6. Establish canonical secret-detection and URL-safety primitives for the
   current consumers; broader network architecture remains separate follow-up.

Any later ref that changes these owners must update this map together with the
affected route documentation and behavioral evidence.
