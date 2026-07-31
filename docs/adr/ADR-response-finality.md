# ADR: Typed Response Finality for Remote No-Action Turns

Status: Accepted for v0.8.2 I3A

## Context

GitHub issues #96 and #98 report one failure class: a remote planner can return
a plan, tool-selection commentary, or evidence-handling narration in message
content without delivering the answer the user asked for. The current planner
correctly parses native tool calls, but when there is no executable action it
treats arbitrary provider message content as `assistant_response`. A later
response helper recognizes and trims some known narration phrases.

That helper cannot establish answer finality. Whether free-form model text is
reasoning, a partial answer, a plan, or a complete answer is a linguistic
judgment over an unbounded input space. Adding Japanese examples, more
tool-routing phrases, or more section delimiters would create the daemon-side
prose classifier prohibited by the Fifth Principle and
`DESIGN-structural-vs-linguistic.md`.

## Decision

For a successful remote planner result that declares native tool-call support
and contains no executable actions, shisad treats provider message content as a
preliminary draft. Before user-visible projection, it makes one bounded
response-finalization request through the accepted planner/provider.

That phase receives the original rendered planner context and the preliminary
draft, but its provider tool set contains exactly one synthetic,
non-executable function:

```json
{
  "name": "respond_to_user",
  "arguments": {
    "final_answer": "..."
  }
}
```

The daemon accepts exactly one native call with that exact name and exact
single-field argument object. It ignores provider message content when the
typed call is valid. `respond_to_user` is a response protocol, not a runtime
tool: it is never registered, sent through PEP, confirmed, or executed.

Invalid envelopes receive only the existing bounded planner repair allowance.
If no valid typed answer is produced, shisad returns its safe planner-validation
failure rather than displaying the preliminary draft or raw provider text.
Every finalization request uses the route's known context capacity and output
reservation before dispatch.

Action-bearing planner responses and post-tool synthesis keep their existing
owners. Deterministic local fallback also remains single-pass. Content-only or
custom routes without declared native tool-call support retain their current
truth-scoped behavior until a separate contract selects a compatible typed
response protocol.

Both planner and finalization phases remain present in redacted traces. Only
the accepted `final_answer` continues through the existing taint,
output-firewall, transcript, audit, and channel-delivery path.

## Security and functionality

The finalizer receives no executable runtime tool schemas, so contextual prompt
injection cannot turn the response phase into a side-effect path. The original
provenance and output enforcement remain intact. The daemon validates only a
closed machine-generated tool-call envelope; it does not decide which words
constitute reasoning or an answer.

This adds one remote model call to applicable no-action turns. The extra call is
accepted because returning a useful answer is a product invariant, while
displaying a fast reasoning dump is not. Known capacity is checked before the
call, retries are finite, local/action paths are unchanged, and the shipped
Shisa route receives an isolated live acceptance journey before closure.

## Consequences

- Remote native-tool-capable no-action turns gain an explicit final-answer
  boundary.
- Provider prose outside the typed call cannot leak through that boundary.
- Semantic answer quality remains the model's job and is checked by behavioral
  and live journeys, not daemon phrase tables.
- Latency and provider usage increase by one call for the selected path.
- Broader structured-output negotiation and content-only finalization remain
  future work.
