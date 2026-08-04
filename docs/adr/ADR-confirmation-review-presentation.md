# ADR: Confirmation Review Presentation

*Status: Accepted for v0.8.2 implementation*
*Date: 2026-08-04*
*Issues: [#74](https://github.com/shisa-ai/shisad/issues/74), [#78](https://github.com/shisa-ai/shisad/issues/78), [#103](https://github.com/shisa-ai/shisad/issues/103)*
*Runtime baseline: `4e004c54`*

## Context

The confirmation system already creates an action-specific safe preview and
structurally excludes internal routing and control fields. Some user surfaces
still obscure that preview with transport details.

Discord repeats confirmation IDs, lifecycle metadata, CLI fallbacks, and the
complete parameter preview even when native Approve and Reject controls are
attached to the owning message. The TUI prints the complete `action.confirm`
RPC result after an ordinary interactive approval, including raw status fields
that the CLI already projects through a safe semantic renderer.

This is a presentation problem. Confirmation authority, proof verification,
pending state, Discord component identity, and tool execution are not moving.

## Decision

1. The existing typed confirmation summary remains the single authority for
   action-specific review text and structural exclusion of internal arguments.
2. A compact review may extract only the closed `Review:` and `Risk Level:`
   labels produced by the structured preview renderer. Missing or malformed
   structure falls back to the bounded tool label, never the raw preview.
3. A Discord message whose native controls cover both approval and rejection
   shows the action review, risk, existing human-facing warnings, and concise
   control instructions. It omits IDs, lifecycle metadata, CLI commands, and
   the full parameter block from primary text.
4. When native controls cannot carry the decision, Discord retains the minimum
   identity and truthful channel/helper fallback required to act. A compact
   card must not claim an unavailable button or proof route.
5. CLI and TUI ordinary `action.confirm` output share one semantic result
   renderer. Safe failures, checkpoints, cooldowns, and useful successful tool
   output preserve their current CLI behavior.
6. The TUI accepts an explicit trailing `--json` on its confirm command. That
   mode displays the existing RPC payload after the same single execution;
   ordinary confirmation output does not expose raw status fields.

## Invariants

- Rendering never authorizes, rejects, replays, terminalizes, or otherwise
  mutates an action.
- Confirmation ID/nonce binding remains present in component metadata and RPC
  payloads even when the ID is absent from native-control primary text.
- Internal argument keys remain structurally excluded from ordinary action
  review.
- Existing security warnings remain visible and distinct.
- Missing controls or unsupported proof collection retain truthful fallback.
- Explicit JSON/details output retains the machine-readable result without
  adding excluded operator diagnostics to the safe failure envelope.
- The renderer consumes finite machine-owned fields. It does not classify user
  intent or arbitrary natural-language meaning.

## Non-Goals

- Changing confirmation policy, proof selection, nonce verification, action
  lifecycle, persistence, audit, execution, or transcript behavior.
- Changing Discord action/message/component identity, message splitting,
  result delivery, or restart accounting.
- A broad CLI/TUI framework rewrite, theme redesign, or persistent pending
  action view.
- Removing machine details from explicit JSON, audit, or operator diagnostics.

## Platform Posture

Python 3.12 is the implementation authority. The presentation seam is
platform-neutral and adds no native-Windows daemon claim, dependency, storage,
transaction, or locking work.

## Acceptance Evidence

- Canonical summary tests cover action-specific reviews and all named internal
  fields.
- Discord exact-byte tests cover complete native controls, partial/missing
  controls, TOTP, recovery-code, expired, and unavailable-backend paths.
- TUI tests cover safe confirmation success/failure, proof-code parsing, and
  explicit JSON details without a duplicate execution.
- Existing CLI renderer tests remain byte-compatible through the shared seam.
- A deterministic daemon journey queues a Discord confirmation, returns the
  compact native-control review, preserves pending identity, and remains out
  of lockdown.
