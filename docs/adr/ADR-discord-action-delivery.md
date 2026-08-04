# ADR: Discord Action and Result Delivery

*Status: Accepted for v0.8.2 implementation*
*Date: 2026-08-04*
*Issues: [#102](https://github.com/shisa-ai/shisad/issues/102), [#105](https://github.com/shisa-ai/shisad/issues/105), [#106](https://github.com/shisa-ai/shisad/issues/106)*
*Runtime baseline: `14c17fd1`*

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
2. Component metadata is revalidated per action immediately before delivery.
   Each confirmation part receives only buttons whose custom IDs bind that
   part's confirmation ID and decision nonce.
3. The adapter builds the owning view at send time. Successful view
   construction selects the native rendering; missing or invalid components
   select the degraded rendering. Text cannot claim controls that the same
   provider send did not attach.
4. Every selected part is split into non-empty content chunks of at most 2,000
   Unicode characters. Splitting prefers the latest paragraph boundary, then
   line boundary, whitespace boundary, and finally a hard boundary.
   Concatenating the chunks reproduces the selected content exactly.
5. A long confirmation part attaches its view only to its final chunk. Result
   parts and preceding confirmation chunks never carry controls.
6. An interaction handle remains available after its acknowledgement. Once
   daemon state shows that the owning action is no longer live pending, the
   adapter releases that handle and removes the originating message's view.
   A non-terminal attempt releases the transient handle without removing
   usable controls.
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
- Changing confirmation policy, proof authority, PEP, execution, audit, or
  other channel behavior.
- Rewriting long model responses. Delivery is bounded regardless of why the
  response is long.

## Platform Posture

Python 3.12 is the implementation authority. Discord behavior is validated at
the adapter boundary with deterministic fakes, including actual view
construction, send ordering, editing, chunking, and provider exceptions. No
live token, dependency, storage schema, custom transaction, or locking
protocol is added.

## Acceptance Evidence

- Adapter tests prove one owning view per confirmation, degraded rendering on
  view-construction failure, final-chunk-only controls, lossless 2,000-character
  chunking, and propagation of partial multi-send failures.
- Daemon tests prove exact visible-action component ownership and separate
  result/action parts.
- Interaction tests prove terminal-only removal of the originating controls.
- A deterministic daemon journey proves that three Discord confirmations
  return three action-specific safe parts without leaking internal reason
  codes.
- Existing delivery lifecycle and replay tests remain authoritative for the
  logical `outcome_unknown` recovery posture.
