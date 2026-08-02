# ADR: Ground Responses in Supplied Evidence Without Disabling Model Prior

Status: Accepted for v0.8.2

## Context

An assistant response can combine several information sources:

- the authenticated current user request;
- prior authenticated user turns in the same session;
- same-turn tool or retrieved evidence; and
- the model's general/background knowledge.

Those sources do not have the same provenance. A useful recommendation supplied
by the user does not establish additional classifications that happen to be in
the model's prior. Presenting those additions as though the user's list or tool
evidence supplied them is a grounding failure, even when an added detail may be
true in the world.

The inverse failure is to suppress model prior entirely. Users should still be
able to ask for helpful background knowledge when no tool call is needed. The
assistant must distinguish the basis of the answer rather than refusing every
claim that was not copied from the current interaction.

## Decision

The runtime keeps source provenance structural and source reconciliation
model-owned.

The daemon supplies separately marked context for the authenticated request,
trusted same-session user context, and untrusted evidence. The composed planner
and typed response-finalization instructions require the model to apply these
rules:

1. Claims actually supplied by the authenticated user or established by
   same-turn evidence may be stated directly.
2. A detail absent from those sources must not be presented as though the user,
   prior conversation, or tool evidence supplied or verified it.
3. When model prior materially adds a claim, the answer identifies it as
   general/background knowledge and states material uncertainty instead of
   silently upgrading it to a verified fact.
4. When supplied facts already answer the question, the response should not be
   padded with unrelated prior classifications.
5. When the user explicitly asks for general knowledge, the assistant remains
   useful and answers with the source distinction intact.

For remote native-tool-capable conversational responses, the existing
`respond_to_user(final_answer)` protocol remains the structural output boundary.
The model performs the linguistic grounding judgment; Python validates only the
closed function-call envelope and passes the typed answer through the existing
output firewall, transcript, audit, and channel path.

## Why the Daemon Does Not Grade the Answer

Determining whether a sentence is supported by supplied evidence, adds model
prior, expresses sufficient uncertainty, or attributes a claim to the correct
source is an unbounded natural-language task. A regex, keyword list, entity map,
token-overlap score, or clause parser would create a second, weaker language
engine in the daemon and would fail on paraphrase, negation, and new domains.

This follows the project rule in
`docs/adr/DESIGN-structural-vs-linguistic.md`: the daemon enforces finite
protocol and provenance structure, while the LLM owns meaning.

## Preserved Behavior

- Untrusted evidence remains data, never an instruction or action authority.
- Prior authenticated user turns remain usable as user-supplied context.
- Model prior remains available when useful or explicitly requested.
- Tool selection, PEP, confirmation, execution, post-tool synthesis, memory
  ownership, local fallback, and content-only provider paths keep their existing
  owners.
- Response finalization still exposes no executable runtime tools and does not
  change the synthetic function name or field set.

## Validation Contract

Deterministic acceptance covers both directions:

- a follow-up answerable from a supplied recommendation does not invent
  unsupported classifications or imply that the list verified them; and
- an explicit request for general knowledge still receives a useful answer
  that distinguishes that prior from supplied evidence.

The reported restaurant journey is a golden test, not a production entity
list. Live acceptance uses the shipped Shisa route because prompt wiring tests
cannot prove that the deployed model expresses the distinction in user-visible
prose.

## Non-claims

This decision does not provide claim-level citations, mandatory external fact
checking, confidence scores, or a universal guarantee that model-prior facts
are correct. It requires truthful use of the provenance available in the
interaction and preserves uncertainty where the model lacks verification.
