# shisad — Design Philosophy

*This document is the first-principles reference for all development on shisad. Every design decision, code change, and review should be evaluated against these principles. When AGENTS.md process rules conflict with these principles, these principles win.*

---

## The Product Goal

shisad exists to let a user do everything they want with an AI agent, as safely as possible.

Both halves matter equally. "Everything they want" is the product. "As safely as possible" is the method. Neither is optional. A framework that is secure but doesn't work is not a product. A framework that works but isn't secure is not shisad.

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

### The Test

For any security mechanism, ask:

1. **Can the user still do what they asked?** If not, the mechanism is broken.
2. **Is the risk actually mitigated?** If the mechanism just blocks the action without addressing the underlying threat, it's theater.
3. **Would an attacker be stopped?** If a legitimate user is blocked but an attacker could bypass it via a different path, the mechanism is worse than useless — it provides false confidence.

### Corollaries

- **Default-grant, enforce-per-call.** Sessions should have all capabilities by default. Enforcement happens at execution time through the PEP pipeline, not by withholding capabilities.
- **Stage gates match authorization, not fear.** If a session is authorized for `HTTP_REQUEST`, the stage1 plan should include `EGRESS`. Stage2 gating applies only to capabilities the session does NOT have.
- **Auto-approve (no confirmation) > confirmation > denial > lockdown.** Normal user-requested actions should just work (no prompt). Confirmation is for first-time/unknown/risky actions and ambiguous provenance. Denial is for actions that are clearly not user-requested (attacker-initiated, hallucinated drift, operator-policy-forbidden). Lockdown is for genuine anomalies (rate limit abuse, forbidden action sequences, max action overflow), not for normal tool usage.
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

Every milestone in the roadmap must pass the behavioral contract before it can close. This is not optional. The sequence is:

1. Behavioral tests pass (the product works)
2. Security tests pass (the product is safe)
3. Static checks pass (the code is clean)

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

Each layer assumes the layer above it has been bypassed. This is the correct model. But "defense in depth" means each layer handles its own failure gracefully — it does NOT mean every layer should independently block the same action "just to be safe." Redundant blocking is not defense in depth; it is a cascade of false positives.

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

shisad is >50K lines. If a user sends "search for news" and gets a lockdown notice, those 50K lines are doing the wrong thing precisely and thoroughly. More code is not the answer. Correct code is.

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
- `README.md` (documentation index)
- `docs/SECURITY.md` (detailed security model)

When these documents conflict on philosophy, this document wins. When they add process detail that doesn't conflict, follow both.
