# shisad — Design Philosophy

*This document governs product and design decisions. Use AGENTS.md and
CONTRIBUTING.md for development procedure. If an approved task conflicts with
these principles, surface the design/scope decision before changing the task;
the principles do not grant authority to expand it unilaterally. Platform,
system, developer, and user instructions retain their applicable precedence.*

---

## The Product Goal

shisad exists to let a user do everything they want with an AI agent, as safely as possible.

Both halves matter equally. "Everything they want" is the product. "As safely as possible" is the method. Neither is optional. A framework that is secure but doesn't work is not a product. A framework that works but isn't secure is not shisad.

### Engineering Objective

Implement the accepted feature set with the smallest clear design that
preserves its behavior, security properties, and supported environments.
Give each shared policy and mutable state one owner. Keep interfaces narrow
and dependencies explicit. Reuse an existing owner before introducing a new
abstraction. Add an extension point when an accepted requirement needs it,
and remove obsolete paths when their supported use has ended.

Judge simplicity by clear ownership and the cost of maintaining supported
behavior, not by line count alone. Preserve independent security properties
and meaningful validation. Apply this objective within the approved scope;
it does not authorize additional refactoring.

---

## Terms (So We Don't Talk Past Each Other)

- **Capability**: a session-level permission to use a class of tools (e.g., `HTTP_REQUEST`, `FS_WRITE`, `SHELL_EXEC`).
- **Resource policy**: operator-defined allowlists/constraints for specific targets (egress hosts, filesystem roots, channel identities, etc.).
- **Stage1 plan**: what the runtime lets the agent attempt without additional confirmation.
- **Stage2 confirmation**: the user-facing approval flow for actions that are not authorized (or are flagged as risky).
- **Lockdown**: an emergency brake for runaway/anomalous behavior; it is **not** the normal way to handle tool denials or configuration gaps.

**Key distinction**: "default-grant" refers to *capabilities*, not *resources*. A session has the capability to use `web.search`, while the specific destination (nytimes.com, evil.com) is a resource-level decision. But resource-level denials must not break the product either — see "Who asked for it?" below.

---

## First Principle: Security Enables Functionality

**A broken product is not a secure product.**

Security through disabling features is not security — it is a broken product disguised as a cautious one. If a user asks "search the web for the latest news" and the agent enters lockdown instead of searching the web, the security system has failed, not succeeded.

The correct response to a risky capability is never to remove it. It is to build enforcement infrastructure that makes the capability safe to use:

- If egress is risky, build confirmation gates and audit trails — don't block all HTTP.
- If shell execution is risky, build sandboxing and confirmation gates — don't block all commands.
- If file writes are risky, build taint tracking and approval flows — don't make the filesystem read-only.

This preserves supported, authorized journeys; it does not bypass explicit
operator policy or mandatory enforcement. If required enforcement is
unavailable, fail the affected action clearly, preserve unrelated work, and
provide the documented recovery or configuration path.

When a capability is disabled, the vulnerability is hidden, not fixed. The user routes around the limitation (using a different tool, a different agent, or no agent at all), and the security infrastructure never gets tested against real usage. Disabled capabilities are technical debt that masquerades as safety.

### Who Asked for It?

The fundamental question for any security decision is: **did the user request this action, or did something else (prompt injection, model hallucination, attacker-controlled input) cause it?**

**"User requested" is a provenance claim, not a phrasing claim.** Treat an action as user-requested only when it is grounded in authenticated user input (i.e., the trusted **USER GOAL** section in spotlighted planner input). Untrusted external content (emails, web pages, tool output, retrieved documents/memory) may *suggest* actions, but it cannot *authorize* them.

- **User says "get me news from nytimes.com"** → the user requested this → it should work.
- **Injected prompt causes agent to visit evil.com** → the user did NOT request this → it should be blocked.

A static allowlist that blocks both cases equally is not security — it blocks the user in case 1 and (correctly) blocks the attacker in case 2, but the user's experience is that the product doesn't work. The allowlist protects against the threat by also breaking the product.

The correct model:

| Scenario | Action |
|---|---|
| Destination on allowlist (pre-approved) | Proceed, audit trail (**no confirmation**) |
| Unknown destination, explicitly requested by user (USER GOAL) | Proceed, audit trail (**no confirmation**) |
| Unknown destination suggested only by untrusted content | **Confirmation gate with warning**: "This link came from untrusted content. Fetch anyway?" |
| Unknown destination with no user attribution (hallucination / plan drift) | Block + actionable error |
| Known-bad destination (exfil patterns) | Block regardless |

The allowlist is an **auto-approve list**, not a hard wall. It is a friction reducer (common destinations proceed with no prompt) and a safe default for unattributed/autonomous actions. When the user explicitly requests a destination in **USER GOAL**, the agent should proceed (subject to per-call enforcement). Confirmation is for ambiguous provenance (e.g., a destination sourced only from untrusted content), not for re-litigating clear user intent.

Routine denial of user-requested actions (when a confirmation gate would safely resolve the ambiguity) is a product failure, not a security feature. Hard denial is reserved for explicit operator policy, known-bad/exfil patterns, or cases where the system cannot safely proceed even with confirmation.

### Scoped Personal Recall

Personal memory and session-derived evidence stay scoped to their owner.
Recall supplies facts and context, never authority for actions. Provenance and
injection taint still constrain its use even when it belongs to the current
user; elevated trust alone must not turn stored text into instructions.

See [Scoped Personal Recall in the security reference](SECURITY.md#scoped-personal-recall)
for the collection, framing, provenance, and legacy-record rules.

### The Chosen Channel Is the Product Surface

A user must be able to complete all regular interactions through their chosen command channel (Discord/Slack/Telegram/Matrix/TUI or the CLI). Any interaction the agent asks the user to complete — approving or rejecting a pending action, recovering from lockdown, checking status, resolving a prompt — must be completable on the channel where it originated. The CLI is a first-class surface, but never the *mandatory* one for ongoing interaction.

**Exceptions:** one-time system setup and credential enrollment (daemon config, factor registration, approval-origin setup) may require the CLI; that is setup, not interaction.

### The Test

For any security mechanism, ask:

1. **Can the user still do what they asked?** If not, the mechanism is broken.
2. **Is the risk actually mitigated?** If the mechanism just blocks the action without addressing the underlying threat, it's theater.
3. **Would an attacker be stopped?** If a legitimate user is blocked but an attacker could bypass it via a different path, the mechanism is worse than useless — it provides false confidence.

### Corollaries

- **Default-grant, enforce-per-call.** Sessions should have all capabilities by default. Enforcement happens at execution time through the PEP pipeline, not by withholding capabilities.
- **Stage gates match authorization, not fear.** If a session is authorized for `HTTP_REQUEST`, the stage1 plan should include `EGRESS`. Per-call policy may still require confirmation for a particular risky action or ambiguous provenance; possessing a capability does not approve every use of it.
- **Auto-approve (no confirmation) > confirmation > denial > lockdown.** Normal user-requested actions should just work (no prompt), subject to per-call enforcement. Confirmation resolves action-specific risk or ambiguous provenance; a destination being new is not enough to re-confirm an explicit user request. Denial is for attacker-initiated actions, unattributed plan drift, operator-policy-forbidden actions, or cases that cannot safely proceed even with confirmation. Lockdown is for genuine anomalies (rate limit abuse, forbidden action sequences, max action overflow), not for normal tool usage.
- **Deny the action, not the assistant.** When a specific action must be denied (attacker-initiated, known-bad destination, missing credentials), deny that action with a clear reason and keep the session healthy. Never cascade a single denial into session-wide lockdown. A denied action is not an anomaly.
- **Lockdown is a last resort, not a default.** If normal usage routinely triggers lockdown, the lockdown threshold is wrong, not the usage.

---

## Second Principle: Behavioral Correctness Is a Hard Requirement

**Code that passes unit tests but doesn't work is not done.**

A test suite that validates "stage2 triggers on EGRESS" and "lockdown fires on plan violation" is testing the security infrastructure. It is not testing the product. Both are necessary; neither is sufficient alone.

### The Behavioral Contract

shisad must pass these behavioral tests at all times. If any of these fail, the release is not shippable regardless of how many unit tests pass:

1. **Basic conversation**: User sends "hello" → agent responds conversationally (no lockdown, no error).
2. **Web search**: User sends "search for the latest news" → agent calls `web.search` → user gets results (when web search is configured).
3. **File read**: User sends "read README.md" → agent reads the file → user gets content.
4. **Memory**: User sends "remember that my favorite color is blue" → agent stores it → later retrieval works.
5. **Multi-tool**: User sends "read the README and search for related projects" → agent uses both `fs.read` and `web.search` without lockdown.

These are not aspirational. They are the minimum bar. If the framework can't do these, it doesn't matter how sophisticated the consensus voting or trace verification is.

When an action fails due to missing configuration (missing credentials, unconfigured integration), the failure must be **actionable** (the user/operator can see what to fix), must not cascade into lockdown, and must not block other tools. A misconfigured integration is not an attack. If the user requested an action that policy forbids, the system must explain that operator decision clearly and provide safe alternatives or an operator approval path — not treat it as an anomaly.

### Milestone Gates

Every runtime milestone in the roadmap must pass the behavioral contract before
it can close. The acceptance requirements are:

1. Behavioral tests pass (the product works)
2. Security tests pass (the product is safe)
3. Static checks pass (the code is clean)

These are evidence obligations, not a required command order. Follow the
validation cadence in [CONTRIBUTING.md](../CONTRIBUTING.md#validation) and the
[maintainer release procedure](PUBLISH.md). A broader valid collection can
supply its contained behavioral and security evidence without separate reruns.
Documentation-only work uses the relevant document checks; completing it does
not establish runtime milestone acceptance.

If a security change breaks behavioral tests, the security change is wrong — not the behavioral tests.

---

## Third Principle: Defense in Depth, Not Defense in Series

The security architecture is layered specifically so that no single layer needs to be perfect:

| Layer | Purpose | Failure mode |
|---|---|---|
| Content firewall (ingress) | Sanitize untrusted input | Malicious input reaches planner |
| PEP pipeline | Validate tool proposals | Unauthorized tool call reaches sandbox |
| Control plane (consensus voters) | Detect behavioral anomalies | Anomalous pattern executes |
| Sandbox | Constrain execution environment | Unscoped execution |
| Output firewall (egress) | Prevent data exfiltration | Sensitive data in response |
| Audit trail | Post-hoc detection | Undetected incident |

Each layer assumes the layer above it has been bypassed and handles its own
failure gracefully. Keep independent defenses for different properties. Authorization
and execution containment may both deny the same request; that overlap does
not make either redundant. Avoid duplicate policy decisions that disregard
established authorization or turn an ordinary denial into session lockdown.

### What This Means in Practice

- The trace verifier's stage1 plan should reflect what the session is authorized to do. It should not independently re-derive a restrictive posture that ignores session capabilities.
- The consensus voters should flag genuine anomalies, not flag normal authorized usage.
- Lockdown should trigger when multiple independent signals converge on a real threat, not when a single stage gate disagrees with the session's own capability set.

---

## Fourth Principle: Measure What Matters

### Good metrics (product health)
- Can the user complete the 5 behavioral tasks?
- How many legitimate requests trigger false lockdowns?
- What percentage of tool calls succeed on first attempt for authorized capabilities?
- Time from user message to useful response.

### Bad metrics (false confidence)
- Number of unit tests passing (if they don't test real behavior).
- Lines of code in security subsystems (complexity is not safety).
- Number of lockdowns triggered (lockdowns are failures, not successes).
- Coverage percentage of internal helper functions.

### The LOC Trap

If a user sends "search for news" and gets a false lockdown, a larger security
subsystem or a higher unit-test count does not make the product work. Measure
the supported user outcome and the security property together.

---

## Fifth Principle: Structure in the Daemon, Meaning in the LLM

The daemon does deterministic work: authenticate, authorize, enforce, audit, sandbox, taint-track, route. Natural-language judgment — intent, valence, topic, negation scope, reconciling a preliminary claim against new evidence — belongs in an LLM.

When a decision in the daemon reduces to parsing free-form prose with regex or edit-distance heuristics, the decision is likely in the wrong layer. Ask whether the decision follows a specified machine grammar (a protocol, schema, or known marker set) or requires interpreting natural-language meaning. A size limit does not make language meaning a machine grammar. If meaning is required, relocate the judgment to an LLM (the COMMAND agent, the planner, the post-tool synthesizer, or a dedicated classifier prompt) and have the daemon enforce the structural consequences (taint, PEP, confirmation, sandbox, audit) around it.

If you encounter this pattern during coding or review, refer to `docs/adr/DESIGN-structural-vs-linguistic.md` for prior incidents, signals, and the syntax-versus-meaning distinction in more detail.

---

## For AI Agents Working on This Codebase

If you are an AI coding agent reading this document:

1. **Functionality is a requirement, not a nice-to-have.** When you implement a security feature, verify that normal usage still works. If your change causes a behavioral test to fail, your change is wrong.

2. **"Secure by default" means "works securely by default," not "blocks by default."** The default state of the system is: all tools available, per-call enforcement active, confirmation gates for risky operations, lockdown only for genuine anomalies.

3. **When in doubt, route to confirmation, not lockdown.** Confirmation asks the user. Lockdown disables the product. One is conservative; the other is destructive.

4. **Test the happy path.** Every feature needs at least one test that proves a user can successfully use it. Security tests that only prove the feature can be blocked are necessary but not sufficient.

5. **Read this document before starting work.** If your implementation plan would break any of the behavioral contract items listed above, stop and redesign.

---

## Document Hierarchy

This document is referenced by:
- `CLAUDE.md` / `AGENTS.md` (development process)
- `README.md` (project overview and documentation map)
- `docs/SECURITY.md` (public security architecture overview)

Use this document to resolve product/design questions and the contributor and
development guides for procedure. Surface a conflicting accepted requirement
for a design/scope decision; follow compatible process detail alongside these
principles.
