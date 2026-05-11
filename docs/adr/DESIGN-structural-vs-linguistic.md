# DESIGN: Structural Enforcement vs Linguistic Interpretation

*Elaboration of the Fifth Principle in `docs/DESIGN-PHILOSOPHY.md`. This doc exists so the principle can stay short in the top-level philosophy doc without losing the working notes behind it.*

---

## The observation

shisad's daemon and the LLMs it orchestrates have different skills. The daemon is good at deterministic work — checking IDs, applying policy, enforcing taint flow, routing messages, auditing. The LLMs are good at interpretive work — figuring out what the user meant, recognising whether two sentences are about the same thing, reconciling a draft claim against new evidence.

When these cross wires — when the daemon is asked to make a judgment that is really about the meaning of natural-language prose — the result is a parallel, lower-quality intent engine that competes with the LLM's judgment. It tends to accumulate edge-case patches indefinitely, because the input space (free-form prose) has no finite specification a regex or rule-set can close over.

Noticing this pattern earlier would have saved real review budget. It is easy to fall into: the fix each time looks like a small localised guard, and only after several rounds does the shape become obvious. This doc is the shared note for catching it sooner.

---

## Prior incidents

Two worked examples from the codebase. Both were eventually fixed by relocating the judgment, not by iterating on the parser.

### 1. v0.7.1 C1 — Confirmation-command pre-parser

**Shape.** The daemon pre-parsed user text in command chat for confirmation intent — `confirm N`, `reject N`, `yes`, `no`, `approve`, `deny`, `cancel` — with regex plus edit-distance fuzzy matching. With a pending action in the session, any user message was first run through this parser before reaching the COMMAND agent.

**Failure mode.** Ordinary conversation was intercepted. "no i mean capabilities" was treated as a malformed rejection command. "hey" was fuzzy-mapped toward a confirmation verb and produced "Did you mean 'confirm 1'?". The user couldn't change topics while a confirmation was queued.

**Root cause.** The daemon was trying to classify user intent from free-form English. The COMMAND agent already had to interpret the user's full language (`"read README"`, `"actually cancel that and search instead"`, `"remember my editor is helix"`). The pre-parser was a second, weaker interpreter competing with it.

**Fix.** Stop pre-parsing user intent in the daemon. Route authenticated command-chat messages to the COMMAND agent with the pending-action state available as trusted context. The agent interprets; PEP enforces whatever structured action the agent proposes. See `planning/PLAN-command-no-regex.md` in the shisa-dev repo.

### 2. v0.7.3.1 GH27 RR5–RR14 — Post-tool stale-claim classifier

**Shape.** To guard against a planner that emitted a premature "reservation page does not exist" claim in its pre-tool prose alongside the web recovery tool calls that would actually resolve it, the daemon grew a classifier: `_is_web_pre_tool_absence_claim`, `_is_web_pre_tool_target_absence_claim`, `_has_web_pre_tool_positive_claim`, plus a boolean combinator. The intent was: detect stale absence claims and replace them via post-tool synthesis; keep mixed valid answers on the append path.

**Failure mode.** Ten consecutive `needs_changes` review rounds, each patching a new phrase or boundary. Broad matcher rows, topic conflation (cancellation-policy absence vs reservation absence), negative `found` forms, clause-local vs global negation, clause boundaries on `,`, `:`, newlines, and the token `found`, helper-row parity drift across the three helpers. Each round was a valid finding against the classifier contract. The contract itself was the problem: natural language has unbounded clause-boundary and negation-shape variation.

**Root cause.** The daemon was trying to make a linguistic judgment ("is this planner sentence a stale absence claim, a positive answer, a mixed caveat, or about a different topic?") with regex. That judgment is the synthesizer LLM's job.

**Fix.** Replace the classifier with a structural invariant: if web-evidence tools executed alongside non-empty pre-tool planner prose, that prose is preliminary by construction. Run post-tool synthesis; pass the preliminary prose into the synthesizer as labelled context to reconcile against the evidence. No phrase, token, overlap, or threshold for reviewers to fuzz. See M5B.ADR-1 in `shisa-dev/planning/v0.7/IMPLEMENTATION-v0.7.3.1.md`.

---

## What the two incidents share

- The daemon was making a decision whose *real* input was natural-language prose.
- Each fix attempt looked locally correct and each new finding looked like a legitimate edge case.
- The finding stream was effectively fuzzing the parser's specification, because the specification was English.
- The correct fix in both cases was to relocate the judgment to an LLM and have the daemon enforce structural consequences (routing, taint labels, PEP, confirmation gates, audit) around that judgment rather than duplicating it.

The cost was measured in review rounds. In GH27 specifically, ten `needs_changes` rounds against a daemon-side classifier versus a small structural refactor that made the whole finding class inapplicable.

---

## Signals the pattern is recurring

Worth pausing and asking whether the judgment is in the right layer when any of these show up:

- Review findings for one component are consistently of the form "this other sentence shape could also leak / misclassify / be mishandled."
- Fixes add clause-boundary characters (`,`, `:`, `;`, `\n`, em-dash, parentheses, conjunctions) to a regex.
- Fixes reason about negation scope — "this `no` shouldn't reach that `found`."
- Fixes distinguish topics by keyword ("cancellation-policy absence vs reservation absence").
- The test suite's coverage growth is a list of hand-authored example sentences.
- A stopword list or overlap threshold is being introduced to decide whether two pieces of prose are "about the same thing."
- The helper's behaviour is being described to reviewers in terms like "matches absence-of-target claims" — a semantic description of an English sentence class.

None of these is automatically wrong, but together they're a reliable indicator that the component is classifying prose rather than structure.

---

## What is legitimately daemon-side parsing

The rule isn't "no regex." Regex and lexical parsing are the right tool when the input space is finite and specified by a machine-side contract rather than by free-form language. Examples that fit:

- URL parsing, scheme/host/path extraction, redacting filesystem paths in diagnostic output.
- Code-fence extraction from known markdown containers; detection of structured tool-call syntax leaking into assistant text.
- Action-ID / confirmation-ID / session-ID format validation.
- JSON parsing, schema validation, known-prefix marker stripping.
- Taint-label manipulation, header canonicalisation, env-var name validation.

The common property: the input is produced by code, a schema, or a protocol, and the spec is closed.

## What belongs to an LLM

Examples that have repeatedly shown up as "tempting to parse, but doesn't close":

- Intent classification of user messages.
- Valence of an assistant sentence (positive / negative / absence / hedged).
- Topic attribution (is this caveat about the same target as the tool query?).
- Negation scope across free-form prose.
- Clause segmentation of LLM output.
- Reconciling a preliminary statement against new evidence.
- Referent resolution ("what does 'its page' refer to?").
- Deciding whether two paraphrases refer to the same entity.

For these, the daemon's job is to structurally route the decision to a capable LLM (COMMAND agent, planner, post-tool synthesiser, or a dedicated classifier prompt) and then structurally enforce whatever that LLM produces. Reproducing the LLM's linguistic work in Python tends to produce a weaker duplicate that the daemon then has to arbitrate against.

---

## On defense-in-depth

It's worth noting that a hand-rolled prose classifier and an LLM are **not** independent defense layers. Stacking them doesn't add safety — it adds two ways to be wrong and forces the daemon to pick between conflicting outputs. Real defense in depth for this kind of judgment is: use the LLM for the judgment, then deterministically enforce the *consequences* (taint, PEP, confirmation, sandbox, audit) around it.

This also connects to the first principle ("Who Asked For It?"). Provenance is a claim about *where* a signal came from (authenticated USER GOAL vs untrusted content block), not a claim about *what words it contains*. Phrase-parsing doesn't recover missing provenance; it just produces a new classifier that inherits whatever provenance was (or wasn't) attached to the text.

---

## Practical suggestion

Before adding a regex that decides something about natural-language prose, the cheap check is: is the input space finite and machine-defined, or is it natural language? If natural, the judgment probably wants to move to an LLM and the daemon's role reduces to routing the input in, taint-labelling what comes out, and enforcing structural consequences.

If we end up here again, it's worth citing this doc and the two prior incidents in the implementation plan up front, so reviewer lanes aren't spent getting there the hard way.
