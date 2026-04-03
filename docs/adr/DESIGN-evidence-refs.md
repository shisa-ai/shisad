# Evidence References — Tainted Content Isolation Primitive

*Created: 2026-03-27*
*Status: Design draft*
*Updated: 2026-04-03 — v0.6.0 G0 shipped restart-stable metadata reload, orphan-blob quarantine, and generic unknown-key wrapping fallback; v0.6.0 M6 records the text-first channel rendering contract*

## Problem

When the agent processes untrusted content (web pages, emails, tool output), that content currently enters the LLM context **inline**. Even with taint labels and delimiter-based spotlighting, the raw text persists in conversation history and gets sent to the LLM on subsequent turns. This creates two risks:

1. **Persistent injection surface**: A prompt injection payload embedded in a web page stays in the conversation for every subsequent turn, getting repeated chances to influence the model.
2. **Context pollution**: Large tainted payloads consume token budget across multiple turns even when they're no longer relevant.

## Design: Evidence References

### Core Concept

Tainted content is stored **out-of-band** in a content-addressed evidence store. The LLM context receives only a **reference stub** — a short, opaque identifier plus a brief metadata summary. The user can view the full content through the UI/channel, but subsequent LLM turns see only the stub.

### Data Model

```python
class EvidenceRef(BaseModel):
    """Opaque reference to tainted content stored out-of-band."""
    ref_id: str              # "ev-" + HMAC-SHA256(instance_salt, session_id + ":" + content_hash)[:16]
    content_hash: str        # Full SHA256 of original content
    taint_labels: list[TaintLabel]
    source: str              # e.g., "web.fetch:nytimes.com", "email:inbox"
    created_at: datetime
    summary: str             # Extractive only (never LLM-generated), ≤200 chars
    byte_size: int           # Original content size
    ttl_seconds: int | None  # Auto-evict after N seconds (None = manual only)
```

v0.5 scope note: the salt persists across daemon restarts, but the ref metadata
index was originally in-memory only. v0.6.0 G0 closes that gap with a durable
`refs_index.json` metadata reload path plus orphan-blob quarantine, before the
broader ArtifactLedger work in v0.6.0 M4.
Startup cleanup is non-destructive on unreadable metadata: quarantine/prune only
run after a readable top-level metadata load. Readable but partially malformed
metadata is sanitized and rewritten before cleanup proceeds, and refs whose
backing blobs are missing are dropped during reload instead of remaining as
phantom handles.

### Flow

```
1. Tool returns tainted content (e.g., web.fetch result)
       ↓
2. Content firewall inspects + labels
       ↓
3. EvidenceStore.store(content, taint_labels, source) → EvidenceRef
       (HMAC-authenticated ref ID generated from per-instance salt)
       ↓
4. Planner receives evidence STUB as the tool result — NOT raw content
       [EVIDENCE ref=ev-a1b2c3d4 source=web.fetch:nytimes.com
        taint=untrusted size=14832 summary="Article about AI regulation..."]
       (LLM never sees raw tainted content, even on the fetch turn)
       ↓
5. Transcript entry records EvidenceRef (not raw content)
       ↓
6. User sees full rendered content in their channel/UI
       (delivered separately, not via LLM context)
       ↓
7. Next turn: LLM sees only the stub, not the full content
       ↓
8. If LLM needs to re-examine: explicit tool call `evidence.read(ref_id)`
       → PEP validates HMAC authenticity before allowing access
       → returns content in UNTRUSTED tier for that turn only
       → transcript records with ephemeral tag; context builder strips on next turn
       → does NOT persist in subsequent turns
```

### Evidence Store

Builds on existing `TranscriptStore` blob infrastructure (already content-addressed, already has `blob_ref` and `read_blob`).

```python
class EvidenceStore:
    """Out-of-band storage for tainted content."""

    def store(self, content: str, *, taint_labels: set[TaintLabel],
              source: str, summary: str = "") -> EvidenceRef:
        """Store content, return opaque reference."""

    def read(self, ref_id: str) -> str | None:
        """Retrieve raw content (for user display or explicit re-examination)."""

    def get_ref(self, ref_id: str) -> EvidenceRef | None:
        """Get metadata without reading content."""

    def evict_expired(self, session_id: SessionId, *, max_age_seconds: int = 3600) -> list[str]:
        """Remove refs older than max_age based on created_at timestamp."""
```

### Context Builder Integration

In `_build_untrusted_scaffold_entries()`, when an entry has an evidence ref:

```python
# Instead of:
#   content = "full 15KB web page with potential injections..."
# Emit:
#   content = "[EVIDENCE ref=ev-a1b2c3d4 source=web.fetch:nytimes.com
#               taint=untrusted size=14832
#               summary=\"Article about AI regulation...\"]"
```

The `evidence.read` tool allows the LLM to pull content back when needed — but it enters the context for **one turn only** and is not persisted into subsequent context windows.

### User-Facing Rendering

The channel adapter renders evidence blocks as expandable/collapsible UI elements:

- **CLI**: Shows summary + `[use evidence.read("ev-a1b2c3d4") to view full content]`
- **Discord/Slack/Telegram**: Renders as a collapsed embed/card with source + summary; full content behind "expand" or in a thread
- **TUI**: Dedicated evidence pane (side panel or scrollable section)

The user always sees the full content. The LLM doesn't.

### Channel-Safe Rendering Contract

The canonical representation is the structured `EvidenceRef`, not a particular terminal/card/transcript rendering. That distinction matters because shisad has to support both richer local UIs and text-first chat surfaces with limited formatting affordances.

Rules:

- Keep a structured evidence payload as the source of truth.
- Treat terminal/chat renderers as flatteners from structured fields, not as the canonical store.
- Do not assume markdown widgets, embeds, or per-channel rich UI affordances exist.
- If a renderer uses reparsing at all, it must fail closed and fall back to plain text rather than inventing state from malformed transcript text.
- Unicode glyphs and emoji can be useful optional affordances on text-first surfaces, but they are presentation sugar, not a correctness dependency.

In practice that means Discord/Slack/Telegram/terminal/TUI renderers may differ cosmetically, but all of them should be derived from the same structured evidence object and must degrade cleanly to plain text.

### Why This Works (Security Properties)

1. **Injection payloads get zero direct shots**: A prompt injection in a web page never reaches the LLM context — not even on the fetch turn. The planner receives only the evidence stub (ref ID + extractive summary). The injection has to survive extractive summarization AND firewall inspection to persist — and the summary is generated under the content firewall's control, not copied verbatim.

2. **Token budget efficiency**: A 15KB web page becomes a ~100-token stub on subsequent turns.

3. **Explicit re-examination is auditable**: If the LLM calls `evidence.read`, that's a PEP-gated tool call with taint propagation. The re-read content enters UNTRUSTED tier and triggers all the normal taint flow controls.

4. **TTL-based auto-eviction**: Old evidence refs naturally age out, reducing the attack surface of stale tainted content.

5. **Summary generation is a trust boundary**: The summary is the only tainted-derived text that persists. It MUST be:
   - Extractive only (pull first sentences) — never LLM-generated (LLM summarization of tainted content could preserve injection phrasing)
   - Capped at ≤200 chars
   - Run through content firewall classification before storage
   - If injection patterns detected in the extractive summary: fall back to generic `"Content from {source}, {size} bytes"` stub

### Relationship to Existing Infrastructure

| Existing Component | How Evidence Refs Hook In |
|---|---|
| `TranscriptStore` blob storage | Evidence store reuses content-addressed blob dir |
| `ContextScaffoldEntry` | New entry type with `evidence_refs` field |
| `TaintLabel` tracking | Evidence refs inherit and propagate taint labels |
| Content firewall | Inspects content before storage; inspects summary before stub emission |
| PEP | Gates `evidence.read` and `evidence.promote` tool calls; applies taint sink rules |
| Spotlight delimiters | Stubs rendered inside UNTRUSTED tier with delimiter protection |
| Episode compression | Evidence stubs compress well (already small); full content not in episodes |

### New Tool: `evidence.read`

```yaml
name: evidence.read
capability: memory.read
description: "Read the full content of a tainted evidence block by reference ID."
arguments:
  ref_id: string  # "ev-..." format
returns:
  content: string  # Full original content
  taint_labels: list[string]
  source: string
security:
  - Taint labels from the evidence ref propagate to the tool result
  - Content enters UNTRUSTED tier for the current turn only
  - Does NOT persist into subsequent turns (context builder strips on next build)
  - Output firewall applies to rendered content
```

### New Tool: `evidence.promote`

```yaml
name: evidence.promote
capability: memory.read
description: "Promote tainted evidence into persistent conversation context (requires user confirmation)."
arguments:
  ref_id: string  # "ev-..." format
returns:
  content: string  # Full original content
  taint_labels: [USER_REVIEWED]  # Relabeled from original UNTRUSTED
  source: string
security:
  - Requires Stage2 user confirmation (this IS the security gate)
  - HMAC validation on ref_id (same as evidence.read)
  - On promotion, content enters normal transcript context with USER_REVIEWED taint
  - Persists across subsequent turns (intentionally — user approved this)
  - Write-sink confirmation rules still apply to USER_REVIEWED content; egress remains governed by the normal destination/goal policy
```

`evidence.promote` fills the gap between "stub forever" and "evidence.read every turn." When the user has reviewed content and wants the LLM to work with it across turns, they approve the promotion. This aligns with the design philosophy: confirmation gate for clear user intent, not lockdown.

### Implementation Estimate

| Component | LOC | Complexity |
|-----------|-----|-----------|
| `EvidenceRef` model + `EvidenceStore` (persistent salt) | ~90 | Low — builds on existing blob store |
| Context builder integration + planner guidance | ~50 | Medium — modify `_build_untrusted_scaffold_entries` |
| `evidence.read` tool | ~30 | Low — standard tool with taint propagation |
| `evidence.promote` tool + Stage2 gate | ~60 | Low — builds on evidence.read pattern |
| Summary generation (HTML-aware extractive) | ~80 | Medium — HTML stripping + sentence extraction + firewall check |
| Channel rendering (CLI stub) | ~20 | Low |
| Tests (unit + adversarial) | ~190 | Medium |
| **Total** | **~520** | |

### What This Enables (Demo Story)

"Watch what happens when the agent fetches a web page with an embedded prompt injection:

1. The content is stored in our evidence store — the user can see it, but the LLM gets only an HMAC-authenticated reference stub. The injection payload **never enters the LLM context** — not even on the fetch turn.
2. On subsequent turns, only the stub persists. The injection payload had zero direct shots at the model.
3. If the agent needs to re-read it, that's an explicit tool call through PEP — HMAC-validated, audited, taint-tracked, and the content only enters context for that one turn before being automatically stripped.
4. If the user trusts the content and wants the agent to work with it long-term, they can **promote** it — that's a user-confirmed action that moves the content into persistent context with a `USER_REVIEWED` taint label. The user is explicitly accepting the risk for that specific content.

No other framework does this. In OpenClaw, Hermes, or Manus, that injection payload sits in the conversation history for every subsequent turn, getting repeated chances to compromise the agent."

---

## Non-Goals (for initial implementation)

- Streaming evidence (chunked large content) — defer
- Cross-session evidence sharing — defer
- Evidence encryption at rest (existing blob store permissions are sufficient for now)
- Evidence search/query beyond `evidence.read` — defer
