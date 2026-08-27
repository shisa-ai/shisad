# ADR: User-Facing Error Messages

*Status: Accepted and shipped in v0.8.2*
*Date: 2026-08-04*
*Issues: [#101](https://github.com/shisa-ai/shisad/issues/101), [#104](https://github.com/shisa-ai/shisad/issues/104)*

## Context

Several runtime paths expose machine-oriented failure details as ordinary
assistant prose. A planner-route exception reaches the deterministic local
fallback as an untyped string, where HTTP status, provider guidance, and a CLI
doctor command are embedded in the primary reply. Separately, a successfully
accepted confirmation whose action then fails is projected as
`confirmation failed`, conflating approval with execution and exposing a raw
tool status code.

The action lifecycle and provider layers already know the structural facts
needed to explain these failures. User surfaces should render those facts
without interpreting exception prose, parsing arbitrary tool output, or
discarding the raw diagnostics that operators and explicit machine-oriented
surfaces still need.

## Decision

1. The core defines a small structured error record with a stable code, safe
   summary, retryability, safe next action, approval outcome, execution
   outcome, and partial-result flag.
2. Operator diagnostics may accompany the in-process object, but Pydantic
   serialization excludes them. Ordinary user renderers use only the safe
   summary and next action.
3. Provider route failures are classified from the documented, machine-generated
   provider error format. HTTP 408, 429, 5xx, connection failures, and unknown
   route errors are retryable temporary failures. Other 4xx responses require
   setup attention. Raw status, route, response body, credential guidance, and
   doctor commands remain out of primary text.
4. A deterministic local action produced during route fallback sets
   `partial_result=true`. The safe route notice remains beside its pending or
   completed result without claiming the sibling action failed.
5. Invalid planner output uses one generic safe retry response. Schema,
   native tool-call formatting, repair-attempt, and planner implementation
   details remain diagnostic-only.
6. Once confirmation evidence is valid, approval is `accepted` independently
   of execution. A failed or unknown action result carries that accepted
   approval outcome plus its separate execution outcome. Unknown execution is
   not safely retryable because an immediate retry could duplicate an effect.
7. Discord and ordinary CLI text render the safe error record. Explicit
   JSON/details output retains existing machine status fields and the safe
   record, but never the excluded operator diagnostics.
8. A known unconfigured web-search backend maps to an actionable setup-then-
   retry response. It remains an ordinary tool/configuration failure and
   does not trigger lockdown or disable unrelated tools.

## Invariants

- Approval acceptance, execution start, execution success/failure/unknown,
  retryability, and partial completion remain separate structural states.
- Primary output never includes operator diagnostics, raw HTTP/provider
  bodies, provider URLs, credential instructions, schema paths, or raw tool
  status codes from these failure paths.
- Existing raw status fields remain available to explicit machine-oriented
  consumers; the safe error record does not replace lifecycle state.
- Accepted approval followed by execution failure is not described as an
  approval failure and does not leave the terminal action pending for replay.
- Partial failure wording does not erase or misstate completed or pending
  sibling work.
- Configuration and execution failures do not change lockdown state,
  action authorization, confirmation verification, audit, persistence, or
  output-firewall behavior.
- Classification is limited to finite machine-owned status/error formats. No
  regex or keyword table decides user intent or other natural-language
  meaning.

## Non-Goals

- A universal exception hierarchy or a rewrite of every historical error
  string.
- Removing machine-readable `status`, `status_reason`, tool output, trace, or
  logging details from explicit diagnostics surfaces.
- Changing provider retry policy, confirmation requirements, action lifecycle
  transitions, tool configuration, or channel delivery ownership.
- Inferring whether arbitrary model prose is safe, retryable, partial, or an
  approval statement.
- Adding a custom transaction or locking protocol.

## Compatibility

Implementation and release tests use Python 3.12. The error record and
renderers are platform-neutral. This decision adds no native-Windows daemon
claim.

## Implementation

```text
docs/adr/ADR-user-facing-failure-presentation.md
src/shisad/
├── cli/main.py
├── core/
│   ├── api/schema.py
│   ├── failure_presentation.py
│   └── providers/
│       ├── base.py
│       └── local_planner.py
└── daemon/handlers/
    ├── _impl_confirmation.py
    └── _impl_session.py
tests/
├── behavioral/test_behavioral_contract.py
├── integration/test_runtime_completion.py
└── unit/
    ├── test_chat_confirmation.py
    ├── test_cli_main.py
    ├── test_failure_presentation.py
    ├── test_handler_confirmation.py
    ├── test_providers_extracted.py
    └── test_session_message_phases.py
```

The integration test directly exercises invalid planner output.

## Verification

- Provider tests cover HTTP 400/401/403/408/429/5xx, connection failure,
  redacted serialization, safe primary text, and partial local-tool fallback.
- Session tests prove only trusted provider metadata can preserve a
  route-failure notice beside pending work; a spoofed text prefix is not an
  source of trusted state.
- Confirmation tests cover accepted approval followed by successful, failed,
  and unknown execution outcomes without changing terminal lifecycle state.
- Discord and CLI tests prove primary text distinguishes approval from
  execution and excludes raw codes while JSON retains machine status.
- Behavioral coverage exercises invalid planner output and an unconfigured
  web-search backend through `session.message`, including normal lockdown and
  actionable primary output.
- First-principles tests cover the change. Isolated live evidence repeats the
  supported Shisa route's strict-output failure and records semantic-quality
  observations separately from deterministic safety tests.
