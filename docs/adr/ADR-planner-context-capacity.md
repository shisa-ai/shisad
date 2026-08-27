# ADR: Planner Context-Window Limits and Compaction

*Status: Accepted and shipped in v0.8.2*
*Date: 2026-07-31*
*Issue: [#97](https://github.com/shisa-ai/shisad/issues/97)*

## Context

The planner currently sends its composed system prompt, the rendered current
request/context scaffold, and every enabled tool schema without checking the
selected model's total context capacity. The reported default Shisa route sent
17,514 input tokens to a model with a 16,384-token context window. The provider
returned HTTP 400; the routed provider logged the raw error, treated it as a
generic route failure, fell back locally, and told the user to check
connectivity or credentials.

The planner input is not one interchangeable prose blob. It contains trusted
safety/tool instructions, authenticated current user intent, required tool
schemas, trusted structural frontmatter, and several optional historical or
retrieved context sources. Capacity handling must preserve those trust
boundaries rather than truncating the request blindly.

## Decision

1. Planner route capabilities may declare `context_window_tokens` and an
   `output_reserve_tokens` value. The exact shipped default Shisa planner
   preset/endpoint/model resolves to its known 16,384-token window when remote
   routing is enabled. Explicit capability configuration wins. Overridden
   endpoints and unrecognized models do not inherit a guessed window.
2. For a known/configured window, the planner assesses the complete outbound
   request: composed system messages, rendered user/context messages, enabled
   tool schemas, protocol framing, and the output reservation. The estimate is
   deterministic and upper-biased for ordinary text. It combines a byte
   baseline with structural code-point accounting for ordinary non-ASCII text,
   per-byte treatment for symbols and other uncommon code points, and
   worst-case treatment for opaque alphanumeric/punctuation shapes. It is an
   admission boundary, not a claim to reproduce every provider tokenizer
   exactly.
3. When optional context makes the request exceed the input budget, the
   runtime removes complete context entries in a deterministic order:
   conversation history and episode summaries first, then thread-resume and
   active-attention content, then retrieved memory, then remaining optional
   same-scope/task-detail context. It records which entry classes were omitted
   and never supplies a partial entry as if it were complete.
4. Capacity compaction never removes or rewrites:

   - the composed safety/system instructions;
   - the authenticated current user goal;
   - a tainted current-turn copy required by the spotlight boundary;
   - trusted security/session frontmatter; or
   - an enabled tool schema required for the current policy/tool surface.
5. If those protected contributors cannot fit with the output reservation,
   the provider is not called. The user receives a structured response
   that names the configured context-window size and suggests shortening the
   request or selecting a larger-context model. It does not expose the route,
   raw provider payload, credentials, or internal control-plane details.
6. Unknown-window routes are not compacted against an invented limit. If the
   provider returns a structurally recognized context-capacity error, that
   error becomes the same terminal capacity error. The planner does not
   retry the identical oversized request and the routed provider does not
   convert it into a generic local fallback.
7. Provider overflow classification is restricted to the finite
   machine-generated HTTP error surface. It does not inspect user prose or
   make a natural-language intent decision.

## Invariants

- A known-limit request is sent only when the estimated full input plus output
  reservation fits the configured context window.
- Optional history/evidence yields before authenticated current intent,
  trusted safety framing, or required tool definitions.
- Current-goal and spotlight trust boundaries remain byte-visible in any
  compacted request that reaches a provider.
- Capacity failure is a request/configuration condition, not an attack; it
  does not trigger lockdown or disable unrelated future turns.
- A provider-reported capacity failure causes at most one remote call for that
  planner attempt and is not described as connectivity, credential, rate
  limit, or transient provider flakiness.
- Logs and user-visible responses contain only safe capacity details, not
  the raw provider body or endpoint.
- No regex, keyword table, edit-distance check, or token-overlap heuristic is
  added for user intent or other natural-language meaning.

## Unknown Model Limits

When the limit is unknown, the runtime does not invent a smaller one. It
preserves the request and lets the configured provider decide its
capacity. A structurally recognized provider overflow becomes a structured
capacity error. Users who know a custom model's limit can configure it in
the planner capability object to enable proactive compaction and preflight.

## Non-Goals

- Downloading or loading provider-specific tokenizer assets at runtime.
- Guessing context windows for every current or future model name.
- Summarizing optional context with another model call.
- Removing enabled tools merely to make a request fit.
- Truncating the authenticated current request or security instructions.
- Redesigning memory retrieval, episode generation, tool registration,
  provider retry policy outside capacity errors, or the generic UI error model.
- Introducing a custom transaction or locking protocol.

## Compatibility

Implementation and release tests use Python 3.12. The
budgeting algorithm is deterministic and platform-neutral. Supported-platform
tests cover the release; no native-Windows daemon claim is added here.

## Implementation

```text
docs/
├── ENV-VARS.md
├── ROADMAP.md
└── adr/ADR-planner-context-capacity.md
src/shisad/
├── core/
│   ├── context_budget.py
│   ├── planner.py
│   └── providers/
│       ├── base.py
│       ├── capabilities.py
│       ├── routed_openai.py
│       └── routing.py
└── daemon/handlers/_impl_session.py
tests/
├── behavioral/test_behavioral_contract.py
└── unit/
    ├── test_context_scaffold.py
    ├── test_planner.py
    ├── test_provider_capabilities.py
    └── test_providers_extracted.py
```

## Verification

- Under-limit and exact-estimated-limit requests reach the provider unchanged;
  an over-limit request drops only the expected optional
  entries and reaches the provider once within budget.
- An irreducible request preserves the safety prompt, current goal,
  trusted frontmatter, and full enabled tool schemas, makes zero provider
  calls, and returns an actionable capacity response without raw HTTP text.
- An unknown-limit route applies no guessed preflight; one structurally
  recognized 16,384-token provider overflow becomes the structured
  capacity response without local fallback or identical-request retry.
- A long-session `session.message` journey with enough optional
  history to exceed the known model budget still returns a visible answer;
  the provider-observed request retains the current goal/security/tool
  boundaries and records deterministic history omission.
- The nearest accumulated/cross-session context regressions and the named
  first-principles gate remain green. Because this changes live planner-route
  behavior, release verification also records one isolated live long-session
  journey against the supported Shisa route.
