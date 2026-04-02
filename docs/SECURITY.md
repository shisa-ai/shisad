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
   Untrusted ────────▶│   [tokens mix]  │─────────▶ Proposed
   Content             │                 │            Actions
                       └─────────────────┘
                                                       │
   ═══════════════════════════════════════════════════════════
   ║               ARCHITECTURAL BOUNDARY                    ║
   ═══════════════════════════════════════════════════════════
                                                       │
                                                       ▼
                        ┌─────────────────┐     ┌─────────────┐
                        │ Trusted Config  │     │  Security   │
                        │ (policies,      │     │  Analyzers  │
                        │  goals)         │     │ (metadata   │
                        └─────────────────┘     │  only)      │
                                                └──────┬──────┘
                                                       ▼
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
  Channels ──▶ Content Firewall ──▶ Context Builder ──▶ Planner LLM
  (Discord,    (sanitize, score,     (spotlighting:      (untrusted;
   Matrix,      taint-label)          trusted/untrusted    proposes only)
   Telegram,                          separation)
   Slack)                                                    │
                                                             │ proposals
              ┌──────────────────────────────────────────────┘
              │
              ▼
  Action Monitor ◀──▶ Policy Enforcement Point (PEP) ◀──▶ Confirmation UI
  (guardrail;         (8-layer pipeline;                   (human-in-the-loop)
   detection only)      hard enforcement)
                              │
                              │ approved actions only
                              ▼
                        Tool Executors ──▶ Output Firewall ──▶ User
                        (sandboxed)       (DLP, secret/PII
                              │            redaction)
                              ▼
                        Memory Manager
                        (gated writes,
                         taint-preserved)
                              │
                              ▼
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

Structured cross-boundary fields are also constrained by semantic tool-schema
types. Sink-critical arguments such as URLs, command tokens, workspace paths,
evidence refs, and thread ids are validated as atoms or opaque handles instead
of being accepted as arbitrary free text.

### Output Firewall (egress)

- Secret/credential pattern detection (API keys, tokens, private keys)
- PII redaction for content crossing trust boundaries
- URL/destination validation on outbound content

### Memory Manager (poisoning defense)

Memory is a high-value attack surface. Research ([MINJA](https://arxiv.org/abs/2503.03704), [AgentPoison](https://arxiv.org/abs/2407.12784)) demonstrates that attackers can inject poisoned entries into an agent's long-term memory through normal interaction — no direct database access required. The poisoned entries persist across sessions and can redirect future behavior with high success rates and minimal utility degradation, making the attack hard to detect. For the full literature survey, see [agentic-memory](https://github.com/lhl/agentic-memory).

shisad's defense is **preventive write gating** — making poisoned entries hard to store in the first place, rather than trying to detect and remove them after the fact:

- **Instruction-like pattern rejection**: deterministic filter rejects content that resembles directives ("always do X", "ignore policy", "never do Y") before it reaches storage. Memory stores facts and preferences, never instructions.
- **Provenance-gated writes**: every memory write requires structured provenance metadata (source, origin, actor, timestamp, capability snapshot). Writes from untrusted sources (web content, tool output, email) require user confirmation before persisting to durable storage.
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

Dependencies are pinned via `uv.lock` with SHA256 integrity hashes. Skills are treated as untrusted code: capability manifests declare what a skill can access, PEP rejects undeclared operations, all skill-initiated tool calls go through the same enforcement pipeline as direct actions, and no skill auto-installs without operator review. See `analysis/ANALYSIS-supply-chain.md` for the full analysis.

---

## Implementation Status

The architecture described here is the target design. Current status as of v0.5:

**Implemented**: PEP 8-layer pipeline, taint tracking and provenance labeling, content firewall with YARA rules, output firewall with secret/PII detection, consensus voting (5 voters), egress allowlisting with provenance-aware enforcement, credential broker, destructive command protection, clean-room admin workflows, append-only audit log, default-deny channel identity allowlisting.

**Planned**:

- **Differential execution** (v0.6+) — when suspicious content enters the context and the next proposed action involves egress or side effects, run the same request with and without the suspect content and compare proposed actions. Behavioral divergence is empirical evidence of injection influence. If proposals are identical, the content is not influencing behavior (reduces false positives). If they diverge materially, a third-party evaluator in a clean context (it never sees the suspect content directly) judges whether the divergence is benign or suspicious. This catches subtle goal drift and laundered injection that passes the content firewall — and equally importantly, confirms innocence when content looks suspicious but isn't actually influencing behavior.
- **Full spotlighting with datamarking** — enhanced context builder with per-request cryptographically random delimiters and character-level datamarking of untrusted content
- **Memory write gating with quarantine** (v0.8) — proposed memory writes held in quarantine with provenance review before committing to durable storage; poisoned entries can be identified and removed before they influence future sessions
- **Formal control-plane process isolation** (v0.7.1) — move core enforcement behind an OS-enforced process/container boundary so that even full code execution in the agent sandbox cannot reach the control plane
- **Hardware-backed approval signing** (v0.7.2) — hardware token (e.g., Ledger) signing for high-value operations; operator authentication and artifact signing flows that cannot be spoofed by software

---

## Further Reading

- `DESIGN-PHILOSOPHY.md` — governing first principles
- `analysis/ANALYSIS-security-casestudies.md` — real-world attack patterns mapped to shisad defenses
- `analysis/ANALYSIS-supply-chain.md` — supply chain threat model and mitigations
- `adr/ADR-command-task-architecture.md` — COMMAND/TASK isolation and orchestration security
- `adr/ADR-policy-source-authority.md` — policy merge and authority model
- [agentic-security](https://github.com/lhl/agentic-security) — literature survey on LLM agent security (78 papers, defense taxonomy, production readiness assessment)
- [agentic-memory](https://github.com/lhl/agentic-memory) — literature survey on agent memory architectures and poisoning defenses (29+ references, attack taxonomy, defense recommendations)
