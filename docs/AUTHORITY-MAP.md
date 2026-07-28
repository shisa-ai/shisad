# Runtime Authority Map

This document records selected live authority and ownership boundaries in the
v0.8.1 release-close candidate after the handler-graph and typed-RPC-registry
consolidations. It is not a claim that every route already has one ideal owner.

## Reading the map

- **Ingress authority** authenticates or scopes the caller before work enters
  a session.
- **Decision authority** decides whether a proposed effect may execute.
- **Lifecycle authority** owns durable state transitions and restart behavior.
- **Effect authority** invokes the concrete toolkit, adapter, or executor.
- **Delivery authority** binds a result to its intended surface and target.

Authenticated operator convenience RPCs are not model-callable planner tools,
but their typed arguments now enter the same PEP, control-plane, durable
approved-action, audit, taint, and output-sanitization authorities as equivalent
planner tools. They use short-lived internal sessions rather than replanning
already-structured operator input.

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
| Convenience `web.*` / `realitycheck.*` | Authenticated local operator RPC, descriptor posture, and typed params | [`_impl_assistant.py`](../src/shisad/daemon/handlers/_impl_assistant.py) → direct adapter → PEP/control plane → durable approved-action executor → toolkit URL/configuration/result checks | Short-lived direct session plus shared plan/action/execution audit; stable typed result |
| Convenience `email.*` | Authenticated local operator RPC, descriptor posture, and typed params | Direct adapter → PEP/control plane → durable approved-action executor → configured local MsgVault toolkit | Shared action/execution audit and taint/output handling; MsgVault remains provider-sync authority |
| Convenience `fs.*` / `git.*` | Authenticated local operator RPC, descriptor posture, configured roots, and managed/control-file exclusions; `fs.write` remains admin-only | Direct adapter → PEP/control plane → durable approved-action executor → filesystem/Git toolkit | Shared plan/action/execution audit; stable root, confirmation, and bounded-Git results |
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
| Conversational action intent | COMMAND planner typed tool output, followed by structural session binding and the shared enforcement path in [`_impl_session.py`](../src/shisad/daemon/handlers/_impl_session.py) | The retired thread/note/todo/reminder/filesystem/web/browser/evidence compatibility family is no longer built or substituted from daemon prose; separate finite state-bound confirmation, auth, greeting-response, and recovery protocols remain |
| Canonical secret signatures | [`security/secret_patterns.py`](../src/shisad/security/secret_patterns.py) | One ordered registry recognizes seven finite API-key, token, access-key, JWT, and private-key shapes in supplied text, including the canonical `oauth_access_token` label; it does not decode, normalize, infer entropy/passwords, or classify prose |
| Ingress secret action | [`security/firewall/secrets.py`](../src/shisad/security/firewall/secrets.py) and ingress taint consumers | Uses the canonical signatures for redaction and `USER_CREDENTIALS` taint; ingress preprocessing remains a separate stage |
| Output secret action | [`security/firewall/output.py`](../src/shisad/security/firewall/output.py) | Uses the canonical signatures for redaction and typed findings before separate entropy/path, PII, and URL logic; those other rules are not part of the registry |
| PEP argument DLP | [`security/pep.py`](../src/shisad/security/pep.py) | Uses the canonical signatures to reject matching structured string arguments on planner, administrative tool execution, and typed operator convenience effect paths; this is not a universal claim about every daemon method or encoded variant |
| Absolute URL destination structure | [`core/url_parsing.py`](../src/shisad/core/url_parsing.py) owns the typed scheme, canonical host, explicit port, and userinfo projection used by matching provider, proxy, browser, assistant-web, and PEP paths | Structural parsing is not a network authorization decision; generic relative-reference, approval-binding, display, and other URL helpers retain their different contracts |
| Network address facts | [`security/network_address.py`](../src/shisad/security/network_address.py) owns standard and supported legacy numeric IP parsing, public versus private/special classification, loopback, and the bounded local-name set | A classification does not resolve a hostname, pin DNS, verify a connected peer, or authorize a destination |
| URL/network action layers | Provider base URLs, executor proxy, browser, assistant web, and PEP consume the matching canonical destination/address facts | Each consumer retains its own allowlist, provenance, confirmation, provider-authentication, redirect, DNS, rebinding, credential, connection-scope, reason-code, and audit behavior; reality-check, output firewall, approval origin, A2A transports, and other different-contract consumers are not silently migrated |

The browser subprocess failure-detail sanitizer intentionally remains separate
from the canonical secret registry. It applies broader assignment-name,
short-token, and hexadecimal heuristics to untrusted process diagnostics and
emits only generic `[redacted]` text; it neither classifies canonical families
nor authorizes or rejects an action.

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
   preserving their authenticated functionality. *(Implemented in the current
   tree.)*
5. Replace daemon prose intent interpretation with structured planner-produced
   intent. *(Implemented for the characterized compatibility action family in
   the current tree.)*
6. Establish canonical secret-detection and URL/address fact primitives for
   the current consumers. *(The seven-family secret-signature registry and
   the bounded absolute-destination/address primitives for the five matching
   network consumers are implemented in the current tree. Broader network
   authorization, DNS, and connection architecture remain separate work.)*

Any later ref that changes these owners must update this map together with the
affected route documentation and behavioral evidence.
