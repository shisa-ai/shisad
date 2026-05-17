# DESIGN: Structural Enforcement vs Linguistic Interpretation

*Elaboration of the Fifth Principle in `docs/DESIGN-PHILOSOPHY.md`.*

---

## Rule

The daemon and its orchestrated LLMs have different jobs.

- **The daemon** enforces structure: authentication, authorization, policy, taint flow, routing, audit, sandboxing.
- **LLMs** interpret meaning: what the user wants, whether two sentences are about the same thing, how to reconcile a preliminary claim against new evidence.

When the daemon is asked to classify the meaning of natural-language prose — user intent, assistant valence, topic attribution, negation scope — the input space is unbounded and no regex or rule-set can close the specification. The result is a parallel, lower-quality intent engine that competes with the LLM and accumulates phrase-level patches indefinitely.

The fix is architectural, not lexical: route the judgment to an LLM and have the daemon enforce the structural consequences (taint labels, PEP, confirmation gates, sandboxing, audit) around the LLM's output.

---

## Prior incidents

Both incidents followed the same shape: a localized lexical guard, several rounds of edge-case patches, and eventual resolution by relocating the judgment.

### 1. v0.7.1 C1 — Confirmation-command pre-parser

**Shape.** Daemon pre-parsed user text in command chat for confirmation intent (`confirm N`, `reject N`, `yes`, `no`, `approve`, `deny`, `cancel`) using regex plus edit-distance fuzzy matching. With a pending action in the session, every user message passed through this parser before reaching the COMMAND agent.

**Failure mode.** "no i mean capabilities" was intercepted as a malformed rejection command. "hey" was fuzzy-mapped toward a confirmation verb and produced "Did you mean 'confirm 1'?". Users could not change topics while a confirmation was queued.

**Root cause.** The daemon was classifying user intent from free-form English. The COMMAND agent was already the authoritative interpreter for the user's full language (`"read README"`, `"actually cancel that and search instead"`, `"remember my editor is helix"`). The pre-parser was a second, weaker interpreter competing with it.

**Fix.** Daemon no longer pre-parses user intent. Authenticated command-chat messages route to the COMMAND agent with pending-action state as trusted context. The agent interprets; PEP enforces the structured action the agent proposes. The public behavioral contract is that queued confirmations remain available without preventing ordinary command-chat turns from changing topic.

### 2. v0.7.3.1 Post-tool stale-claim classifier

**Shape.** To catch a planner emitting a premature "reservation page does not exist" claim in its pre-tool prose alongside the web recovery tool calls that would resolve it, the daemon grew a classifier: `_is_web_pre_tool_absence_claim`, `_is_web_pre_tool_target_absence_claim`, `_has_web_pre_tool_positive_claim`, plus a boolean combinator. Intent: detect stale absence claims, replace via post-tool synthesis; keep mixed valid answers on the append path.

**Failure mode.** Ten consecutive remediation rounds, each patching a new phrase or boundary — broad matcher rows, topic conflation (cancellation-policy absence vs reservation absence), negative `found` forms, clause-local vs global negation, clause boundaries on `,`, `:`, newlines, and the token `found`, helper-row parity drift. Each round exposed a valid edge case in the classifier's implicit contract. The contract itself was the problem: natural language has unbounded clause-boundary and negation-shape variation.

**Root cause.** The daemon was making a linguistic judgment ("is this planner sentence a stale absence claim, a positive answer, a mixed caveat, or about a different topic?") with regex. That judgment is the synthesizer LLM's job.

**Fix.** Replace the classifier with a structural invariant: if web-evidence tools executed alongside non-empty pre-tool planner prose, that prose is preliminary by construction. Run post-tool synthesis; pass the preliminary prose to the synthesizer as labelled context to reconcile against the evidence. No phrase, token, overlap, or threshold remains for reviewers to fuzz.

---

## Shared properties of these incidents

- The daemon was deciding something whose real input was free-form natural-language prose.
- Each localized fix looked correct; each new finding looked like a legitimate edge case.
- The edge-case stream was fuzzing the parser's implicit spec, because that spec was English.
- Resolution required relocating the judgment to an LLM and enforcing structural consequences around it.

Cost: in GH27, ten remediation rounds against the classifier versus a small structural refactor that made the entire edge-case class inapplicable.

---

## Signals a component is classifying prose, not structure

Any one of these is suggestive; two or more together is the pattern:

- Review findings for one component are of the form "this other sentence shape could also leak / misclassify / be mishandled."
- Patches add clause-boundary characters (`,`, `:`, `;`, `\n`, em-dash, parentheses, conjunctions) to a regex.
- Patches reason about negation scope ("this `no` shouldn't reach that `found`").
- Patches distinguish topics by keyword ("cancellation-policy absence vs reservation absence").
- The test suite's coverage growth is a list of hand-authored example sentences.
- A stopword list or overlap threshold is being introduced to decide whether two pieces of prose are "about the same thing."
- The helper's behaviour is described to reviewers in semantic terms like "matches absence-of-target claims."

When this pattern appears, reopen the layer question before adding the next patch.

---

## Where regex is the right tool

The principle is not "no regex." Regex and lexical parsing are correct when the input space is finite and specified by a machine-side contract. Examples that fit:

- URL parsing, scheme/host/path extraction, filesystem path redaction in diagnostics.
- Code-fence extraction from known markdown containers; detecting structured tool-call syntax leaking into assistant text.
- Action-ID / confirmation-ID / session-ID format validation.
- JSON parsing, schema validation, known-prefix marker stripping.
- Taint-label manipulation, header canonicalisation, env-var name validation.

Common property: input produced by code, schema, or protocol; spec is closed.

## Where regex is the wrong tool

Decisions that belong in an LLM:

- Intent classification of user messages.
- Valence of an assistant sentence (positive / negative / absence / hedged).
- Topic attribution (is this caveat about the same target as the tool query?).
- Negation scope across free-form prose.
- Clause segmentation of LLM output.
- Reconciling a preliminary statement against new evidence.
- Referent resolution ("what does 'its page' refer to?").
- Deciding whether two paraphrases refer to the same entity.

For these, the daemon's job is to route the decision to a capable LLM (COMMAND agent, planner, post-tool synthesizer, or a dedicated classifier prompt) and then enforce the structural consequences of what the LLM produces. Reproducing the LLM's linguistic work in Python produces a weaker duplicate that the daemon must then arbitrate against.

---

## Defense-in-depth does not cover this

A hand-rolled prose classifier and an LLM are not independent defense layers. Stacking them doubles failure surface (the LLM can be wrong *and* the regex can be wrong) and forces the daemon to arbitrate conflicting outputs. Defense in depth for linguistic judgment is: use the LLM for the judgment, then enforce the structural consequences (taint, PEP, confirmation, sandbox, audit) deterministically around it.

Connects to the first principle ("Who Asked For It?"). Provenance is a claim about *where* a signal came from (authenticated USER GOAL vs untrusted content block), not about *what words it contains*. Phrase-parsing does not recover missing provenance; it produces a new classifier that inherits whatever provenance the text already had, or didn't.

---

## Practice

Before adding a regex that decides something about natural-language prose, ask: is the input space finite and machine-defined, or is it natural language? If natural, the judgment belongs in an LLM and the daemon's role reduces to routing input in, taint-labelling what comes out, and enforcing structural consequences.

When this pattern comes up again, cite this doc and the two prior incidents in the implementation plan up front. That converts the review from "find the next phrase this regex misses" into "verify the structural invariant holds," which is the review that actually terminates.
