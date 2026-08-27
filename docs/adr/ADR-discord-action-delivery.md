# ADR: Discord Action and Result Delivery

*Status: Accepted and shipped in v0.8.2*
*Date: 2026-08-04*
*Issues: [#102](https://github.com/shisa-ai/shisad/issues/102), [#105](https://github.com/shisa-ai/shisad/issues/105), [#106](https://github.com/shisa-ai/shisad/issues/106)*

## Context

Discord confirmation presentation is action-specific, but the delivery seam
previously flattened every pending action into one message and one component
view. That shape made a large batch compete for Discord's per-message
component budget, mixed completed results with still-pending reviews, and left
all controls attached after one interaction resolved.

The adapter also sent the complete response as one content value. Discord's
[message resource](https://docs.discord.com/developers/resources/message)
limits message content to 2,000 characters. A longer response therefore failed
at the provider boundary even though the daemon had already created one
durable logical delivery attempt.

This is a structural delivery problem. Confirmation policy, proof selection,
nonce verification, tool execution, and the underlying durable-delivery state
machine do not move.

## Decision

1. A Discord response is prepared as an ordered list of delivery parts. A
   completed/action result is a non-control part. Every visible pending action
   is a separate confirmation part with its own native and degraded content.
   The daemon removes only the exact machine-generated aggregate pending
   summary; all surrounding finalized notices, warnings, suggestions, and
   result content remain in non-control parts. A durable delivery prefix is
   applied to the first selected part at the adapter boundary.
2. Component metadata is revalidated per action immediately before delivery.
   Each confirmation part receives only buttons whose custom IDs bind that
   part's confirmation ID and decision nonce.
3. The adapter builds the owning view at send time. Successful view
   construction selects the native rendering; missing, partial, invalid, or
   over-bound component sets select the degraded rendering atomically. Text
   cannot claim controls that the same provider send did not attach. Missing
   optional component constructors therefore degrade each action separately
   rather than reverting to one combined response.
4. Every selected part is split into non-empty content chunks of at most 2,000
   Unicode characters. Splitting prefers the latest paragraph boundary, then
   line boundary, whitespace boundary, and finally a hard boundary.
   Concatenating the chunks reproduces the selected content exactly. Empty or
   whitespace-only logical content raises before a provider send; the existing
   durable layer records `provider_attempt_failed` / `outcome_unknown` instead
   of a zero-send delivered result.
5. A long confirmation part attaches its view only to its final chunk. Result
   parts and preceding confirmation chunks never carry controls.
6. An interaction handle remains available after its acknowledgement. Once
   daemon state shows that the owning action is no longer live pending, the
   adapter releases that handle and removes the originating message's view.
   A non-terminal attempt releases the transient handle without removing
   usable controls. If a pre-upgrade aggregate message visibly contains a
   sibling confirmation, terminal handling retains the ambiguous legacy view
   instead of clearing the sibling's controls.
7. All provider sends remain within the existing logical delivery attempt.
   The attempt succeeds only after every send succeeds. Any exception,
   including one after a partial multi-send, propagates to the existing
   `outcome_unknown` delivery result. It is not converted into a fresh replay.

## Invariants

- One confirmation message describes and controls one visible pending action.
- Result content is sent separately and carries no pending-action controls.
- Principal, workspace, delivery target, live state, decision nonce, and
  selected proof route are revalidated before components reach the adapter.
- Invalid component metadata cannot suppress the degraded actionable text.
- Only a terminal interaction can remove its originating message's controls;
  sibling messages are not edited.
- Every Discord content argument is at most 2,000 characters and chunking is
  lossless.
- Internal consensus, monitor, PEP, trace, and audit reason codes remain out of
  primary user-facing result and confirmation content.
- The existing durable attempt is still the sole delivery identity. This
  decision adds no per-chunk receipt, transaction, or lock.
- Part assembly consumes finite machine-owned fields. It does not classify
  user intent or infer meaning from arbitrary prose.

## Failure Semantics

Provider sends are ordered: result chunks first, followed by confirmation
parts in their visible action order. A failure stops later sends and escapes
the adapter. The durable delivery layer records the whole logical attempt as
uncertain because an earlier provider send may already have had an effect.

Discord message editing is best-effort and separate from result delivery. If
the originating interaction message cannot be edited, shisad does not claim
that controls were removed and does not alter the action result.

## Non-Goals

- Per-chunk durable rows, provider receipts, exact provider idempotency, or a
  reconciliation protocol.
- Persisting provider message IDs for later arbitrary edits.
- Replacing Discord's legacy component layout with Components V2, embeds, or a
  broader channel redesign. The existing component model remains within the
  documented [component constraints](https://docs.discord.com/developers/components/reference).
- Changing confirmation policy, proof selection, PEP, execution, audit, or
  other channel behavior.
- Rewriting long model responses. Delivery respects Discord's message limits
  regardless of why the response is long.

## Compatibility

Implementation and release tests use Python 3.12. Discord behavior is validated at
the adapter boundary with deterministic fakes, including actual view
construction, send ordering, editing, chunking, and provider exceptions. No
live token, dependency, storage schema, custom transaction, or locking
protocol is added.

## Verification

- Adapter tests prove one owning view per confirmation, degraded rendering on
  atomic view-construction failure, componentless degraded delivery,
  final-chunk-only controls, lossless 2,000-character chunking, prepared-prefix
  preservation, and propagation of partial multi-send failures.
- Daemon tests prove exact visible-action component ownership and separate
  result/action parts while retaining finalized notices outside the exact
  aggregate pending summary.
- Interaction tests prove terminal-only removal of the originating controls
  and fail-safe retention of legacy aggregate sibling controls.
- A deterministic daemon journey proves that three Discord confirmations
  return three action-specific safe parts without leaking internal reason
  codes.
- Existing delivery lifecycle and replay tests continue to cover
  `outcome_unknown` recovery.
