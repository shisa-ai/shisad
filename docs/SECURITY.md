# shisad — Security Architecture

This document describes shisad's security model at an architectural level. For the governing design principles, see [DESIGN-PHILOSOPHY.md](DESIGN-PHILOSOPHY.md). For the research literature behind these choices, see the [agentic-security](https://github.com/lhl/agentic-security) survey (78 papers, defense taxonomy, recommended defense-in-depth stack).

---

## The Problem

LLMs destroy the instruction/data boundary that traditional computing relies on. In a normal program, code and data are separate — you can't execute data. In an LLM, everything — system prompts, user messages, retrieved documents, tool outputs — becomes a unified token stream. The model processes it all the same way. This is what makes LLMs powerful (they can reason about anything) and what makes them fundamentally insecure (anything can influence their behavior).

A general-purpose agent that has (1) access to private data, (2) exposure to untrusted content, and (3) the ability to take consequential actions is inherently high-risk. This is the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) ([Fowler](https://martinfowler.com/articles/agentic-ai-security.html)). shisad has all three by design — it's meant to be a useful assistant, not a sandboxed demo. The question is not whether the LLM can be tricked (it can), but how much damage it can do when it is.

## The Approach

Since LLMs won't separate instructions from data, the surrounding architecture must re-create the boundary the LLM collapses.

**The LLM is a planner, not an executor.** It can only *propose* actions. A separate control plane *decides* what executes. The control plane never sees injectable content — it operates on metadata only (action types, resource identifiers, timing, sequence patterns). Prompt injection cannot influence approval decisions because the injected content never reaches the components that make them.

```
                       ┌─────────────────┐
                       │   LLM (Planner) │
   Untrusted ─────────►│   [tokens mix]  │─────────► Proposed
   Content             │                 │            Actions
                       └─────────────────┘
                                                       │
   ═══════════════════════════════════════════════════════════
   ║               ARCHITECTURAL BOUNDARY                    ║
   ═══════════════════════════════════════════════════════════
                                                       │
                                                       ▾
                        ┌─────────────────┐     ┌─────────────┐
                        │ Trusted Config  │     │  Security   │
                        │ (policies,      │     │  Analyzers  │
                        │  goals)         │     │ (metadata   │
                        └─────────────────┘     │  only)      │
                                                └──────┬──────┘
                                                       ▾
                                                APPROVE / REJECT
```

This is the same principle as CPU memory protection: we don't try to make programs "not write to protected memory" — we make it architecturally impossible. We are not trying to make LLMs "robust to injection" through clever prompting. Adaptive attackers have been shown to [bypass prompting-based defenses at >90% rates](https://arxiv.org/abs/2510.09023), but even if the defense rates were massively better, say 99.9% or 99.99%, that would mean that every thousandth or ten-thousandth attack would result in a system compromise. Our architectural guarantees and defense-in-depth seek to prevent and contain damage even with a successful injection attack.

---

## Core Question: Who Asked for It?

The product goal and the security goal are the same question: **did the user request this action, or did something else cause it?**

shisad is the user's agent. It exists to do what the user asks with the highest possible fidelity. The entire security architecture — taint tracking, provenance labeling, confirmation gates, privilege separation — is infrastructure to answer that question reliably at every action. User-requested actions should succeed. Actions caused by injection, hallucination, or attacker-controlled input should not. Provenance, not phrasing, determines enforcement: the system doesn't try to decide whether a request "looks legitimate" — it traces where the request actually came from.

This is what distinguishes shisad from both permissive agents (which can't tell the difference between user intent and injected intent) and restrictive agents (which solve the problem by blocking everything). The goal is not to limit what the agent can do — it's to ensure that what it does is what the user actually wanted.

## Security Principles

**1. Content-blind enforcement vs. content-seeing detection.** Security components fall into two categories:

- **Content-blind** (control plane): see only action types, resource identifiers, timing, sequence patterns. Never see file contents, message bodies, or free-form text. These are the hard enforcement boundary. Examples: PEP pipeline, behavioral sequence analyzer, resource access monitor, consensus voting.
- **Content-seeing** (detection): see content to classify, score, or sanitize it. These use classifiers and heuristics, not general-purpose LLMs. They are detection layers, not sole enforcement boundaries — they can flag, escalate to confirmation, or add taint labels, but hard denial requires convergence with a content-blind signal or deterministic policy. Examples: content firewall (injection classifiers), output firewall (secret/PII detection).

Content-seeing components produce only structured metadata outputs (scores, flags, enum labels) — never free-form text that could carry injection back into control logic.

**2. Commit before contamination.** Plans are committed *before* untrusted content is seen. Even if content contains "ignore the plan", the plan is already locked.

**3. Graduated response.** Normal user-goal actions auto-approve (no confirmation). When uncertain, escalate through the confirmation ladder: confirm with the user, deny the specific action if confirmation is refused, escalate to lockdown only for genuine multi-signal anomalies. A false positive that blocks a user-requested action is a product failure.

**4. Privilege-separated control plane.** The runtime uses three privilege tiers: **TASK** agents handle untrusted content in sandboxed, ephemeral contexts. The **COMMAND** agent orchestrates — it holds user intent, dispatches TASKs, and presents results, but cannot modify system configuration. **SUDO** mode is a clean-room elevation triggered by intent detection on authenticated channels — it can modify policy, capabilities, credentials, and configuration, but its context is stripped to the current user message and system instructions only (no summaries, no artifacts, no residual TASK context), and it auto-drops back to normal operation after the privileged action completes. System modification is possible, but only through this constrained privileged workflow — there is no unconstrained self-modification and no agent-writable instruction files. Policies are read-only to the agent in normal operation. Audit logs are append-only.

**5. Stateless context is a security primitive.** LLMs have no persistent memory between turns. We have complete, deterministic control over what the model "knows" at every turn. The model cannot hide state, cannot remember something we've removed, and cannot resist a context rollback. This enables: checkpoint rollback to pre-contamination state, context forking for isolated task agents, selective context construction and taint quarantine, clean-room sessions provably free of tainted content, and differential execution to empirically test whether content is influencing behavior.

**6. Can't leak what you don't have.** Secrets (API keys, tokens, passwords, private keys) are never placed in the LLM context. A credential broker resolves credentials at the HTTP proxy layer — the tool executor sends a request with a credential reference, and the proxy injects the real secret on the outbound hop. The LLM never sees the secret, so even a fully compromised model cannot exfiltrate it. This is invariant I3.

**7. Approvals don't launder provenance.** When a user confirms an ambiguous action, the confirmation authorizes *that specific action* — it does not remove taint labels, change the content's provenance, or grant blanket trust to the source. A confirmed web fetch from an untrusted page does not make the fetched content trusted. Taint persists through the full data lifecycle regardless of intermediate approvals.

Approval decisions are also bound to their origin. When an action is approved,
rejected, or executed through a confirmation path, the audit trail can record
the originating session, task-envelope ID, confirmation ID, decision nonce,
and timestamp. Approval is evidence about *who approved what*, not a trust
upgrade for the underlying content.

Pending approval authority is time-bounded in the supported profile: 1 hour by
default and at most 24 hours, including when a policy requests a longer window.
Legacy pending rows without an expiry are terminalized on first post-upgrade
load and their old decision nonce is invalidated. The action must be requested
again; a TOTP window or approval-web link lifetime is a separate challenge or
capability deadline and cannot extend the pending action.

Decision-nonce migration is restricted to the exact authenticated parent
contract from before that field existed. A current-format contract with a blank
nonce is invalid approval authority and is terminalized.

Approved execution is also crash-aware. Before invoking a tool effect, the
daemon durably records the action digest, approval-evidence hash, execution
attempt ID, result ID, and `executing` state. On restart, only the exact
in-process `time.now` route or a trusted adapter carrying the same persisted
provider idempotency key may receive one bounded automatic recovery call. The
daemon authenticates the post-decision recovery-authority snapshot with a
separate domain under its durable confirmation-evidence HMAC key, then
revalidates the live tool schema, action and retry descriptors, execution
identity, session and principal, current policy, approval evidence, and expiry
before that call. A missing or mismatched recovery authenticator fails closed
to `outcome_unknown` and clears replay authority.
Normal execution and recovery reuse one attempt-scoped control-plane accounting
identity, so history and trace counters record the logical attempt once.
Automatic recovery in v0.8.1 additionally requires that the durable attempt has
no delivery target. Any target-bearing attempt becomes `outcome_unknown`, even
when the stored target appears unchanged, because this release does not claim a
recovered-result delivery or continuation contract. Every other missing,
corrupt, drifted, exhausted, or unclassified case also becomes
`outcome_unknown`; arbitrary web requests, message delivery, dynamic skills,
MCP tools, and other external effects are not replayed merely because they look
read-like or use HTTP GET.

`outcome_unknown` means the external effect may or may not have happened. The
old decision nonce is invalidated, while `shisad action list --status
outcome_unknown` retains known action/attempt/result/provider identifiers and
gives an informed manual-retry instruction. Inspect provider or local evidence
first; retrying means re-requesting the action and satisfying a new approval.
Provider reconciliation is not generally available in v0.8.1, and shisad does
not claim universal exactly-once behavior for arbitrary external services.
Stable provider idempotency keys remain in private durable state and are not
returned by the public pending-action API. If a stable-key adapter contradicts
the first durable control-plane outcome for the same attempt, the action becomes
`outcome_unknown`; the first outcome remains authoritative for history and
trace accounting, and scheduler containment records a failure without consuming
a second logical run. If an uncertain attempt belongs to a scheduled task, that
task is disabled so it cannot automatically repeat the possibly completed
effect; you must reconcile the result before creating or enabling further work.

During a consistent stable-key recovery, the scheduler's original enabled
posture is authenticated and preserved across restart containment. The daemon
restores an originally enabled task only after accounting completes and only
when its run limit still permits another run; an already-disabled task stays
disabled, and uncertainty or contradiction never re-enables it.

Stage-two amendments are correlated to one confirmation and an explicit
execution-attempt idempotency key. Uncertain transport or internal results and
failures before the durable ready transition cancel only the exact correlated
amendment. After control-plane restart, authority remains active only when the
exact correlated attempt key appears in durable trace-action accounting;
aggregate execution by unrelated same-session actions is not reconciliation.

Control-plane history, committed plans, the learned network baseline, and the
independent audit chain use owner-only durable state under the sidecar data
directory. Plan and network snapshots are versioned and checksum-bound; plan
mutations publish before becoming live. History and audit appends are fsynced
before acknowledgement and their complete retained JSONL domains are validated
on startup. Malformed, truncated, semantically invalid, or newer authoritative
state is retained rather than replaced with an empty view: trace, history, and
audit authority fail closed. The network baseline is advisory, so corruption
or publication failure disables further learning and reports an unknown
baseline without stopping otherwise-authorized actions. `shisad status` and
`shisad doctor check --component control_plane` expose the aggregate and each
domain's typed load/degradation state while the daemon remains available for
diagnosis.

Concurrent confirmation clicks for one action are serialized by an in-memory
per-confirmation lock while that daemon process is running. That lock is a
local concurrency guard, not durable exactly-once evidence; the persisted
attempt/result lifecycle above is the restart authority.

Skill and self-modification activation state is also durable authority. The
skill inventory and self-modification inventory use checksum-bound, owner-only
atomic snapshots, and publish candidate activation or rollback truth before the
live tool registry or persona overlay changes. Malformed, semantically invalid,
or newer snapshots are retained in place and fail closed; they are not treated
as an empty inventory. If self-modification activation truth is uncertain,
dynamic skill registrations are withdrawn because the two authorities cannot
be safely reconciled in that process.

Self-modification proposal, change, and incident records use the same
old-or-new publication boundary. A broken requested proposal or change is
reported as corrupt or unsupported rather than missing. Inspect `shisad status`,
`shisad doctor check --component skills`, and `shisad doctor check --component
selfmod` before restoring a trusted snapshot or explicitly resetting a state
domain.

Auxiliary security-control artifacts use narrower contracts based on their
role. Pairing requests are owner-only append records whose file and containing
directory are fsynced before acknowledgement; generated
pairing proposals and delegated-task artifacts are owner-only old-or-new files
published before their paths are returned. Dashboard false-positive marks are
a checksum-bound atomic snapshot. Corrupt or newer marks are retained and mark
mutation is blocked, while the underlying audit alerts remain available;
inspect `shisad status` or `shisad doctor check --component dashboard` before
restoring or explicitly resetting that marks file. These artifacts do not block
daemon startup and do not create a universal recovery or exactly-once guarantee.

Daemon-owned memory and timeline SQLite databases are admitted through one
owner/symlink-checked filesystem boundary. Their immediate directories are
created or repaired to `0700`, database files to `0600`, and existing journal,
WAL, and SHM companions are validated and restricted to `0600`; first-created
SQLite companions inherit the already-restricted database mode. A symlink,
multi-link/non-regular inode, foreign-owner database or immediate directory, or
group/world-writable non-sticky ancestry fails closed regardless of ancestry
ownership. Directory components are opened relative to held verified directory
descriptors; SQLite connects through the verified database descriptor and must
report the exact claimed main path before callers may use it, keeping later
journal/WAL/SHM names in the claimed family. This contract applies to shisad's
memory databases under its claimed data tree, not to external SQLite products
such as a separately managed msgvault database.
Default session-archive directories and exported archive files are likewise
created owner-only (`0700`/`0600`). A custom export destination is expanded and
normalized once. Its parent remains at its operator-selected restrictive mode,
but must be a non-symlink, owner-controlled, non-group/world-writable directory
(or a shared sticky directory); the archive inode itself must be owner-only and
single-link.

An append failure after pairing-request bytes may have been written blocks
further pairing publication in that daemon process instead of blindly retrying
an uncertain effect. An unterminated retained row also blocks pairing
publication on startup. Inspect the channel doctor diagnostics, reconcile the
retained artifact, and restart before retrying. This blocks pairing publication
for all not-yet-allowlisted identities; already-allowlisted channel operation
remains bounded by its normal policy.

**8. Context control is a first-class security primitive.** Because we construct the LLM's context each turn, we can choose exactly what the model sees — and more importantly, what it *doesn't* see. This is unique to LLM-based systems and has no equivalent in traditional software. Evidence references are the primary application: large untrusted content (web pages, email bodies, tool output) is stored out-of-band in a content-addressed evidence store, and the LLM receives only an opaque reference stub with metadata. The raw tainted content never enters the conversation history, so it cannot persist as an injection surface across turns. When the model needs to re-examine content, it makes an explicit `evidence.read` tool call — which goes through PEP enforcement and returns content into a single-turn isolated context, not the persistent transcript. This turns the usual LLM limitation (no persistent memory) into a security advantage: we can quarantine, exclude, or replace any piece of context at any time, and the model cannot tell the difference.

---

## Threat Model

### Attack Categories

| Category | Vector | Mitigation Layer |
|----------|--------|-----------------|
| Direct injection | User input | Content firewall + PEP |
| Indirect injection | External content (web, email, tool output) | Content firewall + spotlighting + taint tracking |
| Memory poisoning | Conversation / RAG | Memory manager (gated writes, provenance) |
| Tool abuse | Legitimate tool calls with malicious arguments | PEP + capability scoping + argument DLP |
| Exfiltration | Egress channels | Output firewall + egress allowlisting + taint sink enforcement |
| Multi-step chains | Orchestrated action sequences | Behavioral sequence analyzer + rate limiting + consensus |
| Supply chain | Malicious skills, upstream packages | Vetting + lockfiles + provenance/signing + sandbox |

### Security Invariants

These hold regardless of LLM behavior:

- **I1**: No outbound communication includes high-sensitivity content unless user-approved
- **I2**: Untrusted content cannot trigger new privileges
- **I3**: No tool call arguments contain raw secrets (tokens, API keys, passwords)
- **I4**: Silent forwarding is impossible (no hidden BCC, auto-forward, share-to-anyone)
- **M1**: Long-term memory writes are gated (user approval or strict schema)
- **M2**: Memory stores facts/preferences, not instructions
- **M3**: Memory is attributable (source, timestamp) and reversible
- **S1**: No third-party extension executes on a sensitive path without review or pre-approved provenance
- **S2**: All skill-initiated actions go through the PEP (no supply-chain bypass)

---

## Enforcement Architecture

```
  Channels ──► Content Firewall ──► Context Builder ──► Planner LLM
  (Discord,    (sanitize, score,     (spotlighting:      (untrusted;
   Matrix,      taint-label)          trusted/untrusted    proposes only)
   Telegram,                          separation)
   Slack)                                                    │
                                                             │ proposals
              ┌──────────────────────────────────────────────┘
              │
              ▾
  Action Monitor ◄──► Policy Enforcement Point (PEP) ◄──► Confirmation UI
  (guardrail;         (8-layer pipeline;                   (human-in-the-loop)
   detection only)      hard enforcement)
                              │
                              │ approved actions only
                              ▾
                        Tool Executors ──► Output Firewall ──► User
                        (sandboxed)       (DLP, secret/PII
                              │            redaction)
                              ▾
                        Memory Manager
                        (gated writes,
                         taint-preserved)
                              │
                              ▾
                         Audit Log
                        (append-only,
                         tamper-evident)
```

### PEP Pipeline (8 layers, every tool call)

1. **Registry check** — is this a known, registered tool?
2. **Schema validation** — do the arguments match the tool's typed schema?
3. **Capability check** — does this session have the capability class for this tool?
4. **DLP / argument scanning** — do the arguments contain raw secrets? (Not general PII — a personal assistant routinely handles names and emails in tool args. This catches API keys, tokens, passwords, private keys.)
5. **Resource authorization** — object-level access control; planner-proposed resource IDs are treated as untrusted and verified server-side
6. **Egress allowlisting** — provenance-aware destination enforcement (see below)
7. **Credential host-scoping** — credentials resolved by the broker at the proxy layer, never exposed to LLM context
8. **Taint sink enforcement** — provenance-aware rules at egress sinks (user-goal → proceed; autonomous/unattributed → confirm; attacker-initiated → block)

### Consensus Voting (5 independent voters)

Multiple content-blind analyzers must converge before escalation:

| Voter | What it sees |
|-------|-------------|
| Behavioral Sequence Analyzer | Action patterns (read-then-exfil, rapid tool switching, unusual combinations) |
| Resource Access Monitor | Resource access per session (file paths, URLs, memory keys); flags anomalous breadth or sensitivity jumps |
| Execution Trace Verifier | Proposed actions vs. committed plans; flags plan violations and capability scope overflows |
| Network Intelligence Monitor | Egress metadata (destination reputation, frequency, timing) without seeing content |
| Consensus Voting | Aggregates all signals; escalation requires multi-voter agreement |

An attacker would need to fool all voters simultaneously. Each sees a different metadata slice.

### Content Firewall (ingress)

- HTML/text normalization (strip hidden text, zero-width chars, Unicode canonicalization)
- Prompt injection classifiers (ML-based detection + YARA pattern rules)
- Risk scoring (not just pass/fail)
- All output taint-labeled with provenance for downstream enforcement

Channel receive pumps durably reserve a frozen provider-scoped replay identity
before dispatch. The identity binds a non-secret account fingerprint, the raw
provider tenant and delivery domain, an event variant, and the raw provider
message ID. Telegram chat/topic, Slack team/channel, Discord guild/channel
ordinary-message, Discord component/modal interaction, and Matrix account/room
scopes are derived inside their adapters. Discord interactions use raw
`interaction.id` under a distinct event variant. Confirmation, action, and
nonce fields remain lifecycle-binding metadata; source-message and
component/modal fields are non-authoritative interaction context. None can
manufacture replay identity. Direct `channel.ingest` uses a separate identity
derived from the authenticated local RPC peer and fixed server route; caller
channel metadata cannot impersonate or widen a provider scope. Missing or
adapter-mismatched identity blocks dispatch.

Configuration construction and the shared CLI config builder derive paths
without creating or mode-repairing daemon targets. Service construction first
publishes an owner-only, same-host lifetime claim in a registry independent of
the target data directory. The baseline claim covers the canonical data root,
control socket, effective approval-factor store, and configured writable SOUL
path. The data root is treated as a contained tree; external approval/SOUL
files also reserve their component-owned atomic temp, retained-corruption,
backup, tombstone, migration, and lock name families. Unexpected exact,
ancestor, derived-name, and live inode/hardlink overlap fails before target
initialization, while ordinary disjoint siblings remain usable. After claim
publication, a missing data root is created owner-only and an existing
owner/non-writable root may be restricted to `0700`; an existing group- or
world-writable data root fails closed before chmod or contained legacy-state
inspection. Owner-controlled
external authority files are restricted to `0600` only after claim publication;
symlinked, foreign-owner, or non-regular trust files fail closed.
Read-only policy, allowed-signer, and enabled A2A private-key inputs are not
lifetime-claimed, so disjoint daemons may share them, but one daemon cannot
place any of those inputs inside or on a derived name of its own mutable
authority footprint.

An existing control path is removed only when it is an owner socket that refuses
a stream connection. The server holds an identity descriptor for the socket it
creates and cleanup unlinks only that same object, so delayed shutdown cannot
remove a successor or an unrelated file. If an assistant filesystem root
contains claimed control state or trusted policy/signer/A2A private-key inputs,
startup emits a visible preflight warning and the direct `fs.write` surface
blocks the data tree, authority registry, exact trust inputs, and reserved
external-file artifacts;
legitimate changes continue through their dedicated admin routes. The daemon
claim remains held until mutable services and listeners stop. This is a local
mutable-file authority boundary, not a multi-host or remote provider-account
lease.

The local claim does not prevent another host or process outside that filesystem
from using the same remote bot/account. Telegram polling startup failures and
terminal Slack, Discord, or Matrix consumer-task failures mark the adapter
disconnected, retain a non-secret exception type in channel health, and appear
as degraded `shisad doctor check --component channels` status. This makes a
provider-reported duplicate consumer/session failure visible without claiming
that shisad holds a distributed provider lease.

The contained control-plane sidecar inherits a duplicate of that exact locked
claim record across `exec`, verifies the owner-only record identity and its
exact data-root candidate before sidecar mutation, and retains the descriptor
until its listener and control-state writers stop. Graceful daemon shutdown
joins the sidecar before releasing the parent's claim reference. If the parent
dies abruptly, the inherited descriptor keeps the visible registry record
active until the sidecar's parent watcher completes shutdown; releasing only
the parent reference cannot unlink a record that still has an inherited lock
holder. Sidecar fallback cleanup is bound to the socket inode captured after
readiness and does not unlink a replacement socket.

`restart --fresh-config` reloads the candidate configuration before writing its
secret-bearing prior-config snapshot. It reserves the prior data/backup tree and
the complete refreshed authority set in one bounded same-host admission, then
creates the backup directories and snapshot as owner-only durable state. After
publication it narrows that same locked registry record to the exact refreshed
set and transfers the live claim into the first daemon run; debug autoreload
iterations after the first acquire normally only after the prior run has fully
released its claim. Admission timeout or backup failure starts no refreshed
daemon and does not initialize a disjoint refreshed data root.

A successful handler records a terminal outcome; a failed or uncertain handler
retains an uncertain outcome. Reserved, terminal, and uncertain records are
non-evicting authority, while the bounded 2,048-entry recent set is only an
optimization. Eviction, compaction, and restart therefore cannot make a known
identity fresh. Valid old unscoped state continues to reject known raw IDs but
blocks unknown admission in that provider scope until an explicit operator
rebaseline with `shisad channel replay-rebaseline --channel <scope> --confirm`;
it is not silently migrated. Replay snapshot/journal corruption,
unsupported schema, or reservation persistence failure is retained and blocks
that scope. `shisad doctor check --component channels` reports provider and
direct-ingress replay posture.

### Context Builder (spotlighting)

Three-tier prompt layout: trusted instructions, internal state, untrusted content. Uses random delimiters and datamarking to make it structurally harder for the model to treat data as instructions. Based on the [Microsoft Spotlighting](https://arxiv.org/abs/2403.14720) approach.

### Credential Broker

Secrets never enter the LLM context. Tools reference credentials by opaque handle; the credential broker resolves handles to real secrets at the HTTP proxy layer on the outbound hop. The LLM sees `credential_ref: "gmail_oauth"`, not the actual token. Even if the model is fully compromised and tries to exfiltrate credentials, it has nothing to exfiltrate — the secret exists only in the proxy's memory, scoped to the specific tool and destination host that needs it.

For delegated TASK sessions and persisted scheduler/background tasks, credential
use is narrowed again by the immutable task envelope: the envelope carries an
explicit `credential_refs` allowlist, and the PEP denies missing or
out-of-scope refs fail closed. Tool grants do not imply credential grants.

### Evidence References (context isolation)

Large untrusted content is stored out-of-band in a content-addressed evidence store. The LLM context receives only a short reference stub with metadata (`[EVIDENCE ref=ev-a1b2c3d4 source=web.fetch:nytimes.com taint=untrusted size=14832 summary="..."]`). The raw tainted content never enters the conversation transcript, eliminating persistent injection surface. When the model needs to re-examine content, it calls `evidence.read(ref_id)` — which goes through PEP enforcement and returns content into a single-turn isolated context. This dramatically reduces the token-budget cost of tainted content and limits each injection payload to a single exposure window.

Internally this now lives in a structured ArtifactLedger rather than an
ad-hoc blob map. The ledger persists artifact lifecycle state and endorsement
metadata alongside the ref. Endorsement is narrow by design: a user-endorsed
artifact may pass the `evidence.promote` confirmation seam on later reuse, but
endorsement does not strip taint, upgrade provenance, or make the artifact
globally trusted.

The ledger treats its salt, versioned reference index, referenced blobs, and
quarantine records as one evidence domain. On restart it publishes references
only after validating that complete domain. Missing, malformed, mismatched, or
unsupported companion state therefore degrades evidence operations only:
ordinary daemon operation remains available, while evidence validation, reads,
promotion, and cleanup fail closed and retained bytes are left untouched.
Operators can inspect the typed reason with `shisad status` or
`shisad doctor check --component evidence`; recovery requires restoring the
matching domain state or performing an explicit whole-domain reset through an
approved administrative/test workflow.

Structured cross-boundary fields are also constrained by semantic tool-schema
types. Sink-critical arguments such as URLs, command tokens, workspace paths,
evidence refs, and thread ids are validated as atoms or opaque handles instead
of being accepted as arbitrary free text. These semantic atom checks protect
the planner / TASK orchestration path and structured TASK-return boundary; the
explicit admin `tool.execute` surface is a separately trusted operator path
with its own policy and audit controls.

Delegated TASK output crosses a second boundary before it can influence the
COMMAND transcript: the TASK raw response must pass through a mandatory
summary-firewall checkpoint, and the resulting summary checkpoint artifact is
persisted before the sanitized summary is handed back. If the checkpoint cannot
be produced, the handoff fails closed instead of letting an unchecked TASK
summary enter the orchestrator context.

### Output Firewall (egress)

- Secret/credential pattern detection (API keys, tokens, private keys)
- PII redaction for content crossing trust boundaries
- URL/destination validation on outbound content

### Memory Manager (poisoning defense)

Memory is a high-value attack surface. Research ([MINJA](https://arxiv.org/abs/2503.03704), [AgentPoison](https://arxiv.org/abs/2407.12784)) demonstrates that attackers can inject poisoned entries into an agent's long-term memory through normal interaction — no direct database access required. The poisoned entries persist across sessions and can redirect future behavior with high success rates and minimal utility degradation, making the attack hard to detect. For the full literature survey, see [agentic-memory](https://github.com/lhl/agentic-memory).

shisad's defense is **preventive write gating** — making poisoned entries hard to store in the first place, rather than trying to detect and remove them after the fact:

- **Instruction-like pattern rejection**: deterministic filter rejects content that resembles directives ("always do X", "ignore policy", "never do Y") before it reaches storage. Memory stores facts and preferences, never instructions.
- **Provenance-gated writes**: every memory write requires structured provenance
  metadata (source, origin, actor, timestamp, capability snapshot). High-risk
  external-source writes such as web content, tool output, and email route to
  confirmation or review when the trust matrix requires it. Session-derived
  conversation-summary extraction is provenance-marked; when the session has a
  complete owner tuple, resulting writes are owner-scoped. By default, the
  summarizer attempts writes through an auto-accepted ingress path, but each
  proposed memory write still passes write policy and can be allowed, rejected,
  or require confirmation. Operators can disable automatic extraction with
  `SHISAD_MEMORY_AUTO_EXTRACTION_ENABLED=false` or raise
  `SHISAD_MEMORY_AUTO_EXTRACTION_CONFIDENCE_THRESHOLD`.
- **Subagent write restriction**: task agents handling untrusted content cannot write to long-term memory directly — they can only propose writes via structured outputs with provenance pointers. The orchestrating agent reviews proposals in a clean context with no untrusted content present. This structurally breaks the MINJA attack chain where the agent's own reasoning stores malicious entries.
- **Taint persistence through storage**: provenance and taint labels are immutable properties of stored entries. Processing, summarizing, or combining content does not upgrade its trust level — derived content inherits the most restrictive taint of its sources.
- **Append-only corrections**: updates create new records referencing what they supersede, preserving full history for audit and rollback. No silent overwrites.
- **Tiered storage**: different memory types (episodes, facts, task state, constraints, procedures) have different trust semantics and write postures. Procedural/experience memory — the highest-risk tier for instruction mimicking — is isolated with strict firewall and quarantine defaults.

---

## Trust Boundaries

| Boundary | What crosses it | Enforcement |
|----------|----------------|-------------|
| Untrusted ingress | Web pages, emails, API responses, tool output | Content firewall + taint labeling |
| LLM boundary | Constructed context → proposed actions | Not a security boundary; assume compromised |
| Model provider | Prompts sent to LLM API endpoints | Endpoint allowlisting; HTTPS for remote; no raw credentials in prompts |
| Tool boundary | Approved proposals → actual execution | PEP pipeline; sandboxed executors |
| Egress boundary | Anything leaving the system | Output firewall + provenance-aware taint sink rules |
| Persistence boundary | Memory / vector DB / logs | Gated writes; taint preserved; append-only audit |

For TASK and background sessions, the task envelope is itself part of the trust
boundary. It carries capability scope, credential refs, resource-scope ids /
prefixes, and untrusted-trigger policy. Background runs still go through the
same PEP pipeline, but the envelope can force confirmation or rejection when an
untrusted event payload tries to drive autonomous execution.

---

## Egress Model

The egress model answers "who asked for it?" at every outbound action:

| Scenario | Action |
|----------|--------|
| Destination on allowlist (pre-approved) | Proceed, audit trail (no confirmation) |
| Unknown destination, explicitly requested by user | Proceed, audit trail (no confirmation) |
| Unknown destination suggested only by untrusted content | Confirmation gate with warning |
| Unknown destination with no user attribution (hallucination/drift) | Block + actionable error |
| Known-bad destination (exfil patterns) | Block regardless |

The allowlist is an auto-approve list and a safe default for autonomous actions. It is not a hard wall for explicit user requests.

---

## Clean-Room Workflows (SUDO mode)

Privileged operations (config changes, capability grants, credential management, skill installs) trigger SUDO mode — a clean-room session that:

- Is stripped to the current user message and system instructions only (no summaries, no artifacts, no residual TASK context, no memory retrieval except trusted config state)
- Triggers automatically via intent detection on authenticated channels (the agent cannot self-escalate)
- Produces only a structured diff/proposal (never applies changes directly)
- Is enforced by deterministic validators and explicit approval before commit
- Auto-drops back to normal operation after the privileged action completes

This is what makes system modification safe without making it impossible. The COMMAND agent in normal operation has no tools to modify its own constraints. SUDO mode provides those tools, but only in a context provably free of tainted content — so even if an attacker has influenced the agent's reasoning in normal operation, that influence cannot carry into the privileged workflow.

## Destructive Command Protection

Certain catastrophic command patterns (e.g., `rm -rf /`) are blocked structurally at the sandbox/policy layer before execution, not by LLM judgment. Protected path registry, severity-tiered detection, and recursive deletion scope analysis ensure no prompt injection, jailbreak, or misconfiguration can make the agent destroy a host filesystem.

## Supply Chain

Dependencies are pinned via `uv.lock` with SHA256 integrity hashes. Skills are
treated as untrusted code: capability manifests declare what a skill can
access, PEP rejects undeclared operations, all skill-initiated tool calls go
through the same enforcement pipeline as direct actions, and no skill
auto-installs without user review.

As of the published `v0.6.0` line, the CI/release path is also materially
hardened: GitHub Actions are pinned by SHA, CI runs dependency-review on PRs,
workflow linting (`zizmor`), and GitHub code scanning, and the public release
path goes through GitHub Actions `publish.yml` using PyPI OIDC trusted
publishing with release-time dependency audit, SPDX SBOM generation, and build
provenance attestations. The manual upload path still exists only as an
emergency fallback and does not carry the same provenance guarantees. See
`docs/AUDIT-supply-chain.md` and `analysis/ANALYSIS-supply-chain.md` for the
full analysis.

---

## Implementation Status

The architecture described here is still the target design. Current status as
of the published `v0.6.0` line:

**Implemented**:

- PEP 8-layer pipeline, taint tracking and provenance labeling, content
  firewall with YARA rules, output firewall with secret/PII detection,
  consensus voting (5 voters), egress allowlisting with provenance-aware
  enforcement, credential broker, destructive command protection, clean-room
  admin workflows, append-only audit log, and default-deny channel identity
  allowlisting.
- Formal `COMMAND` / `TASK` orchestration boundaries in the live runtime:
  immutable task envelopes, taint-safe handoffs, task-scoped credential refs,
  typed sink validation for built-in runtime boundaries, live resource-scope
  enforcement, TASK summary-firewall checkpoints, and approval provenance on
  confirmation/execute audit paths.
- Structured evidence / artifact handling: restart-stable evidence metadata, a
  structured ArtifactLedger with endorsement metadata and GC semantics, and
  text-first evidence rendering that keeps large untrusted content on the
  extractive path by default.
- Baseline high-risk tool surfaces now ship in the same enforcement model:
  web search/fetch, confirmation-gated browser writes with source/destination
  binding, and local skill tool-surface integrity checks via persisted
  schema-hash validation.
- Supply-chain and deployment hardening for the shipped line: pinned workflow
  actions, CI dependency review + workflow linting + code scanning, release-time
  dependency auditing, PyPI OIDC trusted publishing, SPDX SBOM generation, and
  provenance attestations.

**Planned**:

- **Minimal control-plane isolation boundary** (`v0.6.1`) — move core policy /
  PEP / audit enforcement behind an OS-enforced process boundary without
  breaking the current behavioral contract.
- **PromptGuard 2 / stronger semantic classifier integration** (`v0.6.1`) —
  harden the semantic-classifier path without turning it into the sole
  enforcement boundary.
- **Tool Dependency Graph verification + phantom action detection** (`v0.6.1`)
  — add stronger metadata-only runtime checks tying tool calls back to the
  committed user-goal plan and surfacing deny-pattern compromise signals.
- **Differential execution** (post-`v0.6.1`) — when suspicious content enters the context and the next proposed action involves egress or side effects, run the same request with and without the suspect content and compare proposed actions. Behavioral divergence is empirical evidence of injection influence. If proposals are identical, the content is not influencing behavior (reduces false positives). If they diverge materially, a third-party evaluator in a clean context (it never sees the suspect content directly) judges whether the divergence is benign or suspicious. This catches subtle goal drift and laundered injection that passes the content firewall — and equally importantly, confirms innocence when content looks suspicious but isn't actually influencing behavior.
- **Full spotlighting with datamarking** — enhanced context builder with per-request cryptographically random delimiters and character-level datamarking of untrusted content
- **Memory write gating with quarantine** (`v0.7`) — proposed memory writes held in quarantine with provenance review before committing to durable storage; poisoned entries can be identified and removed before they influence future sessions
- **Hardware-backed approval signing** (`v0.6.2`) — hardware token (for example Ledger) signing for high-value operations plus user-authenticated artifact approval flows that cannot be spoofed by software

---

## Further Reading

- `DESIGN-PHILOSOPHY.md` — governing first principles
- `analysis/ANALYSIS-security-casestudies.md` — real-world attack patterns mapped to shisad defenses
- `analysis/ANALYSIS-supply-chain.md` — supply chain threat model and mitigations
- `adr/ADR-command-task-architecture.md` — COMMAND/TASK isolation and orchestration security
- `adr/ADR-policy-source-authority.md` — policy merge and authority model
- [agentic-security](https://github.com/lhl/agentic-security) — literature survey on LLM agent security (78 papers, defense taxonomy, production readiness assessment)
- [agentic-memory](https://github.com/lhl/agentic-memory) — literature survey on agent memory architectures and poisoning defenses (29+ references, attack taxonomy, defense recommendations)
