# shisad - Development Guide

This `AGENTS.md`/`CLAUDE.md` covers ground rules, development process, and behavior notes for AI coding agents.
See `README.md` and `docs/` for project-specific details and reference material.

Instruction precedence: if `AGENTS.md` conflicts with platform/system/developer instructions, follow platform/system/developer instructions.

## First Principles — READ THIS FIRST

**Read `docs/DESIGN-PHILOSOPHY.md` before starting any work.** It is the governing document for all design decisions.

The short version: shisad exists to let a user do everything they want with an AI agent, as safely as possible. **Both halves matter equally.** A framework that is secure but doesn't work is not a product. Security through disabling features is not security — it is a broken product.

When your implementation would break any of these behavioral requirements, stop and redesign:
1. User sends "hello" → agent responds (no lockdown)
2. User sends "search for news" → agent searches (when web is configured)
3. User sends "read README.md" → agent reads the file
4. User sends "remember X" → agent stores it, later retrieval works
5. Multi-tool requests work without lockdown for authorized capabilities

During ordinary runtime work, run the affected tests and the named
first-principles gate when the shared product contract can be affected:
`uv run pytest tests/behavioral/test_first_principles_gates.py -q`.

Broad behavioral/full-suite and live evidence are checkpoint/release gates,
not after-every-edit defaults. A broader valid run subsumes contained tests;
never rerun the same behavioral selection merely to accumulate another green
command.

**If a security change breaks functionality, the security change is wrong — not the functionality.**

## Project Overview

shisad is a security-first AI agent framework. The goal is to build a robust, production-quality system that lets users accomplish real tasks with AI agents while defending against the fundamental risks of autonomous agent deployment:

- **Functionality**: The agent must actually do what the user asks — securely, but it must do it
- **Security**: Prompt injection defense, data exfiltration prevention, per-call enforcement
- **Reliability**: Hot-reloadable skills/plugins, proper connection management, graceful degradation
- **Memory**: Structured storage with semantic search, not raw markdown files
- **Observability**: Comprehensive logging, audit trails, anomaly detection

### Design Principles

See `docs/DESIGN-PHILOSOPHY.md` for the full rationale. Summary:

1. **Security enables functionality** - A broken product is not a secure product; never disable capabilities as a substitute for building safe enforcement
2. **Default-grant, enforce-per-call** - Sessions have all capabilities by default; enforcement happens at execution time through the PEP pipeline
3. **Auto-approve (no confirmation) > confirmation > denial > lockdown** - Normal user requests should just work; confirm only for first-time/unknown/risky actions; deny attacker-initiated or policy-forbidden actions; lockdown is for genuine anomalies only
4. **Defense in depth** - Layer multiple defenses; assume any single layer can be bypassed; but redundant blocking is not depth, it's false positives
5. **Behavioral correctness is a hard requirement** - Code that passes unit tests but doesn't let users complete tasks is not done

## Key Directories

```
shisad/
├── src/              # Core Python source
│   └── shisad/       # Daemon, control plane, security, skills
├── tests/            # pytest test suite
│   ├── unit/         # Component tests
│   ├── integration/  # Cross-component runtime flows
│   └── adversarial/  # Prompt injection / exfil / evasion cases
├── scripts/          # Validation + metrics helpers (coverage, assets, parity)
├── docs/             # Public design, roadmap, and operator docs
│   ├── adr/          # Architectural decision records / design docs
│   ├── analysis/     # Curated public analysis docs
│   ├── runbooks/     # Operator runbooks
│   ├── DESIGN-PHILOSOPHY.md
│   ├── ROADMAP.md
│   ├── USE-CASES.md
│   ├── ENV-VARS.md
│   └── TOOL-STATUS.md
└── examples/         # Example configurations and skills
```

## Development Philosophy

### Spec → Plan → Test → Implement

Every non-trivial feature follows this cycle:

1. **Spec**: Define requirements in `docs/` before coding
2. **Plan**: Create implementation plan with affected files tree
3. **Test**: Write tests BEFORE implementation
4. **Implement**: Write minimal code to pass tests
5. **Validate**: All tests must pass
6. **Commit**: Atomic commits with passing tests only

### Security-First Development

Security features must not break functionality. Both are tested together:

- **Threat model first**: Before implementing features, consider attack surface
- **Test the happy path too**: Every security feature needs at least one test proving authorized users can still complete their task
- **Test adversarial cases**: Include prompt injection attempts in test suites
- **Review trust boundaries**: Every input channel is potentially adversarial
- **Audit sensitive operations**: Log all tool calls, especially egress
- **Confirmation, not lockdown**: When a security mechanism needs to intervene on authorized usage, route to user confirmation — never silently lock down

See `docs/DESIGN-PHILOSOPHY.md` for the full "security enables functionality" principle.

### Interactive / Ad-hoc Development

Not all work starts from a sprint punchlist. Interactive sessions (e.g., human lead working directly with a coding agent) still follow the same development principles, scaled to the change:

**The spec→test→implement loop still applies.** Even for ad-hoc requests:

1. **Track the work outside product documentation.** Use the public issue or
   pull request when the work is intentionally public; otherwise use the
   maintainer's external project tracker or session notes. Never create a
   roadmap, worklog, punchlist, review trace, or agent-memory file in this
   repository merely to track execution.
2. **Write tests first.** Ad-hoc does not mean untested. Write or update tests before implementation — at minimum, cover the success path and any security-relevant edge cases.
3. **Validate before committing.** Run the targeted Python 3.12 tests,
   changed-source coverage, and static checks from the validation matrix. A
   live runner pass is release-close evidence or a recorded milestone exception,
   not an ad-hoc default. Don't commit code that hasn't passed the required
   validation for its scope.

**Post-implementation review is expected.** Ad-hoc commits should receive an independent review pass before any release is cut. This can happen:
- As a follow-up reviewer session against the committed changes
- As part of the next milestone review cycle
- Reviewers should check the public issue/PR, any relevant human-facing ADR,
  and the commit diff to catch behavioral or documentation drift early
- The key point: interactive implementation does not substitute for review — it defers it

**When the change outgrows ad-hoc.** If an ad-hoc request touches multiple
components, changes security-relevant behavior, or grows beyond a single
focused commit, pause for an explicit design and implementation plan. Publish
an ADR only when it is useful to external human readers; keep execution plans
outside this repository.

### Public documentation boundary

All documentation committed here must be useful to a human reader: users,
operators, external developers, security reviewers, contributors, or release
maintainers. Appropriate documents include product and setup guides,
configuration references, runbooks, ADRs, research analysis, contributor
guidance, maintainer procedures, and release history.

Do not commit private roadmaps, milestone plans, worklogs, punchlists,
review-lane records, agent memory, resumption notes, or private process
identifiers. Stable contributor instructions and developer tooling may remain
here when they help external contributors, but they must not contain private
execution history or session-specific instructions. Public issues and PRs may
describe concrete public work; they are not a reason to copy an internal
execution ledger into `README.md` or `docs/`.

README is an overview and navigation surface. Put detailed setup in the
canonical operator guide and link to it. Before release, compare changed docs
with the previous published tag and review them editorially for duplicated
implementation detail, acceptance-test prose, stale phase wording, and
unexplained internal vocabulary.

Do not invent project jargon, acronyms, or workflow labels. Prefer established
ordinary language, and define a necessary domain term the first time it
appears. Temporary review IDs and agent shorthand must not become product
vocabulary. See `CONTRIBUTING.md` for the public documentation style.

## Roles (Planners / Coders / Reviewers)

We use separate lanes for development work:

- **Planner**: defines behavior and implementation sequencing outside public
  product documentation; authors a public ADR only when external readers need
  the design decision.
- **Coder**: owns all implementation patches (code + tests) and repo changes.
- **Reviewer**: analysis-only; must not author implementation patches (no code changes).
- **Human lead**: arbitrates scope, risk, and disagreements; decides what is a blocker vs a deferral.

Rules:
- Reviewers provide findings + rationale + suggested fixes, but do not change the repo.
- Coders translate reviewer findings into tracked issue/PR or external-task
  entries before implementing fixes.
- Coders must triage all reviewer feedback, including notes labeled non-blocking or informational. If the feedback is valid, fix it in the active remediation loop or record an explicit no-change/defer rationale approved by the human lead; severity affects priority, not whether valid feedback can be ignored.
- Reviewer follow-up is confirmation-only (resolved / unresolved with rationale), not code changes.
- For closure purposes, reviewer "green" means no remaining valid open findings for the reviewed scope. "Not a blocker" by itself is not enough if the reviewer also raised a valid issue that remains unfixed and undeferred.

## Workflow Expectations

### Before Picking Up Work

- Check git status/log for recent changes
- Run `git status -sb` and treat its output as the baseline worktree state for this task
- Pre-existing unrelated dirty/untracked files from that baseline are expected and non-blocking
- Review existing docs and tests for context (start with the touched public
  docs and relevant ADRs/runbooks)
- Review any touched-area cleanup backlog or TODO notes in the external task
  tracker when one exists
- Re-review `docs/DESIGN-PHILOSOPHY.md` and explicitly note any product/behavioral-contract implications in the milestone pre-analysis
- Reason through threat hotspots, runtime wiring checkpoints, validation scope,
  and likely deferrals before implementation begins; record that analysis in
  the issue/PR or external task tracker, not a public product doc
- Consider security implications of the change

### During Execution

- Write tests first for new functionality
- Keep commits atomic and focused
- Document security-relevant decisions
- For planner/provider/tool/scheduler/channel/runtime-security changes, identify the nearest deterministic user journey. Plan an isolated live verification pass only for milestone/release close or when the change materially alters live interaction in a way deterministic tests cannot represent.
- **Opportunistic cleanup on file touch**: when editing a file for milestone
  work, remove dead code, stale imports, unused helper methods, and superseded
  approaches in the same file. This is normal hygiene, not scope expansion.
  Document significant removals in the issue/PR or external task notes. If a
  cleanup requires touching files outside the active scope, defer it there.
- **Refactor backlog**: if the touched area already has a backlog or TODO doc, review it at the start of the task. Otherwise use same-file-touch opportunistic cleanup only.

### After Changes (commit on completion)

**When you finish a task, commit.** A "task" is a complete logical unit of work — not every individual file edit. Do not commit mid-task (e.g., while iterating on a fix, exploring questions, or waiting for clarification). Do commit when the task is done and validated, without waiting to be asked. This applies to all completed work — code, tests, docs, planning, config — not just milestone closures.

- Run targeted Python 3.12 tests and changed-source coverage for the changed scope
- Run Ruff on changed Python files and mypy on affected packages; reserve repository-wide static checks for checkpoints
- Run live verification at release close or for a recorded milestone exception where deterministic tests cannot represent the changed interaction
- Run one full Python 3.12 deterministic/coverage pass only at nightly, milestone closure, or an agreed large checkpoint; reuse a green scheduled pass for the exact candidate
- Update relevant docs
- **Commit immediately** after validation passes — do not wait to be asked
- When finishing a milestone or review-remediation scope, follow the closure checklist below and produce the closure commit in the same session

### Validation Cadence and Evidence Reuse

Validation is an evidence ladder, not a cumulative checklist. Duplicate runs
cost time, CI resources, feedback latency, and delivery velocity without adding
assurance. They are an antipattern that must be actively avoided.

A result is bound to its source/test tree, dependency lock, Python version,
operating system, configuration/posture, and test selection. A broader run
subsumes contained selections at the same tree/environment. Different Python
versions, platforms, optional-dependency postures, and live harnesses are
distinct evidence. Repeat a selection only after relevant changes, to diagnose
a suspected flake, when required evidence was not captured, or by explicit
human-lead request; "more confidence" alone is not sufficient.

Required cadence:

- Failed test/remediation: reproduce the exact node IDs; after fixing, rerun
  those nodes and collect coverage for behaviorally changed production
  modules. Widen once to the owning file/keyword slice or nearest contract
  journey only when the fix can affect it.
- Localized feature/bug: affected unit/contract tests plus the nearest distinct
  integration or behavioral journey, with changed-module coverage.
- Shared runtime/security primitive: the targeted evidence above, relevant
  integration/behavioral selection, and first-principles gates. This does not
  imply the whole suite.
- Nightly/milestone/agreed checkpoint: one full deterministic Python 3.12 pass
  with global coverage and `-rxXs` reporting. This pass contains unit,
  integration, adversarial, behavioral, and first-principles tests; do not run
  those subsets again.
- Release close: one final full Python 3.12 coverage pass, relevant
  supported-platform checks, and applicable live lanes. Python 3.12 is the
  release-gated interpreter; newer Python versions remain best-effort and
  non-blocking until an explicit compatibility gate is restored.

Partial runs do not enforce repository-wide coverage floors because untouched
modules were intentionally not loaded. Inspect changed executable
lines/modules in the targeted report. Apply global and per-module floors only
to the full checkpoint/release collection.

Use one invariant test at the cheapest authoritative layer plus one
representative end-to-end journey. Keep exhaustive corruption, fault, and input
matrices in unit/contract tests rather than repeating them through unit,
integration, and behavioral layers.

### Validation Command Matrix

```bash
# 1) Ordinary fix: exact/focused tests + changed-module coverage on Python 3.12
# Replace these illustrative paths with the affected module/tests.
uv run --python 3.12 pytest tests/unit/test_host_matching.py \
  --cov=shisad.core.host_matching --cov-report=term-missing -q
uv run ruff check src/shisad/core/host_matching.py tests/unit/test_host_matching.py
uv run mypy src/shisad/core/host_matching.py

# 2) Shared runtime/security contract, when affected
uv run --python 3.12 pytest tests/behavioral/test_first_principles_gates.py -q
# Also run the nearest affected integration/behavioral node or keyword slice.

# 3) Milestone/nightly/release checkpoint: ONE full Python 3.12 collection + coverage
uv run --python 3.12 pytest -m "not requires_cap_net_admin" \
  --cov=src --cov-report=term-missing --cov-report=xml -q -rxXs
uv run python scripts/coverage_baseline.py --xml coverage.xml
uv run python scripts/coverage_module_gate.py --xml coverage.xml \
  --critical-floor 80 --module-floor 60
uv run ruff check src/ tests/ scripts/
uv run mypy src/shisad/

# Tool status check (review docs/TOOL-STATUS.md; regenerate with live daemon if available)
# uv run python scripts/live_tool_matrix.py --tool-status

# Release or recorded milestone-exception live runner verification
# Use an isolated daemon instance and record the exact commands + outcomes
# in the issue/PR or external task notes.
RUNNER_INHERIT_SHISAD_ENV=1 \
RUNNER_TMUX_SOCKET_NAME=shisad-dev \
RUNNER_TMUX_SESSION_NAME=shisad-dev \
SHISAD_DATA_DIR=/tmp/shisad-dev-data \
SHISAD_SOCKET_PATH=/tmp/shisad-dev.sock \
SHISAD_POLICY_PATH=/tmp/shisad-dev-policy.yaml \
bash runner/harness.sh start --no-debug
bash runner/harness.sh shisad status
# Exercise the changed behavior via runner/harness.sh or a direct control client.
RUNNER_INHERIT_SHISAD_ENV=1 \
RUNNER_TMUX_SOCKET_NAME=shisad-dev \
RUNNER_TMUX_SESSION_NAME=shisad-dev \
SHISAD_DATA_DIR=/tmp/shisad-dev-data \
SHISAD_SOCKET_PATH=/tmp/shisad-dev.sock \
SHISAD_POLICY_PATH=/tmp/shisad-dev-policy.yaml \
bash runner/harness.sh stop

# Optional asset/parity artifact when relevant
uv run python scripts/yara_parity_report.py --output /tmp/yara-parity.json
```

## Git Practices

- **Commit on task completion** — when a logical task is done and validated, commit without being asked; do not commit mid-task or on every file touch
- **No bylines** or co-author footers in commits
- **Use conventional commits**: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `security:`
- **NEVER** use `git add .`, `git add -A`, or `git commit -a`
- **NEVER** revert, checkout, or restore files you did not modify for the current task
- **ALWAYS** add files explicitly with targeted `git add <file>` commands only
- **ALWAYS** verify staged files before commit using `git diff --staged --name-only`
- **ALWAYS** review the staged diff before commit using `git diff --staged`
- If unrelated changes exist in the worktree, leave them untouched
- Unrelated dirty/untracked files are non-blocking: continue scoped work without pausing, and stage only files for the active task
- Unexpected changes mean new unrelated files/edits that appear after baseline and were not created by commands for the active task
- If higher-priority policy requires a pause/escalation, ask the user; default recommendation is to continue and commit only task-scoped files
- **Atomic commits** - group related changes, separate unrelated ones

### Commit Message Format

```
type: short summary (imperative mood)

- Bullet points for details if needed
- What changed and why
```

Examples:
```
feat: add policy enforcement point for tool calls
security: implement egress URL allowlisting
fix: handle reconnection in Discord channel
test: add prompt injection test cases
```

### Milestone/Remediation Closure Checklist

When asked to close a milestone, review remediation, or release-readiness pass:

0. **One full Python 3.12 checkpoint passes before milestone closure** (or a
   scheduled result is reused for the exact candidate), with global coverage
   and `-rxXs` reporting. Its behavioral/adversarial subsets are not rerun.
0p. **Contained first-principles gates are marker-clean for runtime-facing
   scope**. Run the focused file separately only if the broader pass did not
   preserve auditable marker evidence. These gates cover clean,
   accumulated-state, degraded-web, confirmation-followup,
   require-confirmation, and cross-session postures.
0a. **Release-close validation bundle recorded once per distinct environment**:
   one final full 3.12 coverage pass, relevant supported-platform checks, and
   applicable live lanes unless the human lead narrows scope. Newer Python
   versions are best-effort and are not release gates. Do not separately rerun
   deterministic subsets:
   - `bash live-behavior.sh --live-model -q`
   - `timeout 240s env SHISAD_LIVE_CODING_AGENTS=claude uv run pytest tests/live/test_coding_agents_live.py -q`
   - `timeout 240s env SHISAD_LIVE_CODING_AGENTS=codex uv run pytest tests/live/test_coding_agents_live.py -q`
   - `timeout 240s env SHISAD_LIVE_CODING_AGENTS=opencode uv run pytest tests/live/test_coding_agents_live.py -q`
   Run the live-model and ACP live lanes sequentially, not in parallel; overlapping them can create harness-level startup timeouts and invalidate the evidence.
   If any live lane cannot run, record the exact reason before calling the release closeable.
0b. **Tool status check**: review `docs/TOOL-STATUS.md` — if a tool that was WORKS is now BROKEN, the milestone is not closeable. Regenerate with a live daemon if available: `uv run python scripts/live_tool_matrix.py --tool-status`
0c. **Live runner evidence recorded for runtime-facing release close or a
   milestone exception**: run an isolated `runner/harness.sh` pass when the
   release is runtime-facing, or when a milestone materially changed live
   interaction in a way deterministic tests cannot represent. Record the
   reason, exact commands, and outcomes. Ordinary remediation does not trigger
   this lane.
0d. **Valid review feedback closed**: every valid reviewer issue, including non-blocking notes, is either fixed and re-reviewed or explicitly rejected/deferred with rationale approved by the human lead before marking the milestone closeable.
1. Stage only explicit task files: `git add <file> ...`
2. Verify staged file set: `git diff --staged --name-only`
3. Review staged patch: `git diff --staged`
4. Commit with a conventional message
5. Report commit evidence: `git rev-parse --short HEAD` and `git show --name-only --oneline -n 1`
6. Perform tag/push steps only when explicitly requested by the human lead (never assume retag/force-tag by default)
7. If tag/push actions were requested, verify final refs and report them (`git rev-parse --short <branch>` and `git rev-parse --short <tag>`)
8. Before declaring closure, verify every open deferral has a destination:
   - a public issue when external tracking is intended, or
   - the maintainer's external project tracker.
   Do not create a public roadmap/worklog entry only to satisfy this step.
9. For milestone close and release-close, run a refactor-cadence sweep:
   - review any touched-area cleanup backlog or TODO notes in the closing scope,
   - close/update completed cleanup items and add newly discovered on-the-way candidates,
   - keep this opportunistic-only (do not expand closure into standalone refactor scope).
10. For release-close, run an orphan sweep across the release docs:
   - review the issue/PR and external task tracker for unresolved items, and
   - ensure each unresolved item is closed or has a concrete destination
     outside the public product documentation.
11. For release-close, run a docs-parity sweep for top-level operator docs:
   - verify `README.md` and the top-level public docs under `docs/` match current architecture/runtime behavior and release status, and
   - update them in the same closure scope when drift is found.

### Release Publishing

**Follow `docs/PUBLISH.md`** for the full version-bump, build, and publish
checklist. Key points:

- Version must be updated in both `pyproject.toml` and `src/shisad/__init__.py`.
- `CHANGELOG.md` gets a new topmost section per release (no "Unreleased" section).
- Run the full validation gate before building artifacts.
- Never publish from a dirty tree or reuse stale `dist/` artifacts.
- If GitHub CodeQL/code-scanning raises alerts on the release commit or a
  release remediation branch, inspect them with `gh api` before assuming manual
  UI work is required. Use:
  `gh api '/repos/<owner>/<repo>/code-scanning/alerts?state=open&tool_name=CodeQL&per_page=100'`
  and `gh api '/repos/<owner>/<repo>/code-scanning/alerts/<id>/instances'`.
  Only dismiss alerts programmatically after human review confirms a test-only
  hit or false positive, and record the alert IDs plus disposition in the
  issue/PR or external release record when they affect release-close.

## Code Quality

### Before Submitting Code

- [ ] Self-review: is this understandable without explanation?
- [ ] Security: have I considered how this could be abused?
- [ ] Tested: are success, error, and adversarial paths covered?
- [ ] Modular: can each function be understood in isolation?

### Security Checklist for New Features

- [ ] **Does this break any behavioral tests?** If so, redesign. (See `docs/DESIGN-PHILOSOPHY.md`)
- [ ] **Does this disable a capability instead of making it safe?** If so, build enforcement instead.
- [ ] Does this expand the attack surface? Document how.
- [ ] If this expands the attack surface (channels/tools/skills/egress): ship per-call enforcement, audit logging, and at least one realistic adversarial test.
- [ ] Does this handle untrusted input? Apply sanitization.
- [ ] Does this involve egress? Implement allowlisting for auto-approve and confirmation gates for ambiguous/tainted provenance (do not re-add confirmation/denial for clear USER GOAL requests).
- [ ] Does this store data? Consider poisoning attacks.
- [ ] Does this require privileges? Scope minimally.
- [ ] Does this touch secrets? Never add real secrets to prompts/tests/fixtures; use placeholders and verify redaction paths.

### Dependency Management & Supply Chain

Dependencies are pinned via `uv.lock` (committed, with SHA256 integrity hashes). This is the primary defense against supply-chain attacks — `uv sync` installs exact resolved versions with hash verification.

Rules:
- **Always use `uv sync` / `uv run`** — never `pip install` directly. pip bypasses the lockfile.
- **`uv.lock` must stay committed.** If you run `uv lock` or `uv add`, the lockfile changes must be in the same commit as the `pyproject.toml` change.
- **Do not add new dependencies without justification.** Prefer stdlib solutions. Every new dependency is attack surface.
- **`pyproject.toml` uses range specifiers** (e.g., `>=2.10,<3`) for compatibility — this is fine because the lockfile pins the exact version. Exception: `requires-python` can use `>=` (if Python itself is compromised, the lockfile isn't saving us).
- **Review lockfile diffs** when dependencies change. New transitive dependencies should be noted in the commit message.
- **No `--no-verify` or `--no-hashes`** flags on install commands.

## Handling Blockers

If you encounter:
- **Permission issues**: Stop and flag for resolution
- **Test failures**: Fix before proceeding (don't skip)
- **Unclear requirements**: Check docs first, then ask
- **Merge conflicts**: Resolve carefully, test after
- **Security concerns**: Document and flag for review
- **Architecture questions**: Refer to design docs in `docs/`

## Docs, Metrics, and Claim Integrity

- Keep execution checklists, pre-analysis, and milestone state in the issue/PR
  or an external maintainer tracker, never in public product documentation.
- Fix doc↔code drift immediately (especially around security guarantees and runtime enforcement semantics).
- During release-close, explicitly include `README.md` and the top-level public docs under `docs/` in docs-parity review. If dependency resolutions or workflow/action trust anchors changed, include `docs/AUDIT-supply-chain.md` in the same parity pass.
- When writing release stats or quoting numbers (tests, churn, LOC), scope calculations to a specific tag/commit and include the exact commands used.
- **Address end-users as "user" or "you", not "operator"**, in public-facing documentation (`README.md`, `CHANGELOG.md`, `docs/2FA.md`, `docs/USE-CASES.md`, user-facing parts of `docs/SECURITY.md` and `docs/ENV-VARS.md`). "Operator" reads as jargon and makes the reader wonder whether you mean them or a separate software role. It is still appropriate in deployment/admin/runbook docs (`docs/DEPLOY.md`, `runner/RUNBOOK.md`, `docs/runbooks/`) and in threat-model / design docs (`docs/DESIGN-PHILOSOPHY.md`, `docs/adr/`, `docs/analysis/`) where it names a distinct policy-author role separate from the end user. See `docs/PUBLISH.md` CHANGELOG style principle 3 for the long form.

### Claim Integrity (Done/Shipped/Complete)

Any claim of “done”, “shipped”, “complete”, or “closed” must include evidence for all three:

- **Runtime wiring evidence**: where the behavior is enforced in the live runtime path (not just a helper function).
- **Test evidence**: exact validation command(s) + outcomes (include integration/adversarial when relevant).
- **Docs parity evidence**: the issue/PR or external task record is current,
  and security analysis/non-claims are updated when behavior or guarantees
  change.

For runtime-facing release claims, also include live runner evidence: exact
`runner/harness.sh` (or direct control-client) commands + outcomes, or an
explicit human-approved reason it could not run. Ordinary implementation claims
cite the proportional deterministic evidence for their scope; they do not
trigger a live rerun by default.

Truth-in-claims:
- Use truth-scoped wording; do not overclaim universal behavior when behavior is conditional (e.g., degraded runtime, optional backends, feature flags).
- Prefer “when X is enabled” / “in mode Y” / “fails closed when Z is unavailable” over “always/guarantees/prevents”.

### Definition of Done (Security Features)

- [ ] Code implemented (minimal patch)
- [ ] Runtime path wired (daemon/control handler/policy path exercised)
- [ ] Tests green (targeted + changed-source coverage for ordinary work; one full Python 3.12 pass at milestone closure or an agreed checkpoint)
- [ ] Claim-integrity evidence recorded (runtime + tests + docs parity)
- [ ] Any remaining gaps explicitly deferred (see below)

### Deferrals

- Track unresolved items in the public issue tracker when they are intended for
  public collaboration, or in the maintainer's external project tracker.
- Each deferral should include a clear item, rationale, risk, and destination.
- Do not add a `DEFERRALS` ledger, internal milestone ID, or execution backlog
  to README, operator docs, ADRs, or other public documentation.
- Release-close orphan checks must include the active issue/PR and external
  tracking source.
- No orphan deferrals: a deferred item must be linked to an executable destination before milestone/release closure. Accepted destinations are:
  - a public issue with an exit condition, or
  - an external tracked milestone or backlog entry.

### Review Trace (Findings → IDs → Commits)

- Track reviewer findings in the issue/PR or external review record before
  remediation; do not add an internal finding ledger to public docs.
- Convert every valid finding into either a tracked correction or an explicit
  accepted-no-change/deferral note with rationale before closure, including
  findings a reviewer described as non-blocking.
- Use public issue references in commit messages when they help readers trace
  the change. Do not expose private finding IDs.
- Log the exact validation commands and outcomes in the issue/PR or external
  task notes when closing items.

## Meta: Evolving This File

This AGENTS.md is a living document. Update it when:
- You discover a workflow pattern that helps
- Something caused confusion
- A new tool or process gets introduced
- You learn something that would help the next person

Keep changes focused on process/behavior, not project-specific details (those go in docs/).
