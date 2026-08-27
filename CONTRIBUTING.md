# Contributing to shisad

Thank you for improving shisad. This guide describes the public contribution
contract: design principles, development setup, validation, documentation, and
pull-request expectations.

## Start with the product principles

Read [`docs/DESIGN-PHILOSOPHY.md`](docs/DESIGN-PHILOSOPHY.md) before changing
runtime behavior. Shisad exists to let users accomplish what they ask as safely
as possible. Security controls must preserve useful behavior:

- authenticated user requests should work when policy allows them;
- ambiguous or risky actions should use confirmation where that resolves the
  risk;
- one denied action must not unnecessarily disable the whole session;
- enforcement belongs in runtime policy, provenance, sandbox, and audit layers,
  not in fragile natural-language heuristics.

## Development setup

Shisad uses Python 3.12 as its development and release-gating interpreter.

```bash
git clone https://github.com/shisa-ai/shisad.git
cd shisad
uv --no-config sync --frozen --group dev --group channels-runtime
```

`--no-config --frozen` uses the reviewed repository lock instead of ambient uv
configuration. Do not lower dependency security floors to accommodate a stale
package universe.

For local daemon work, the runner provides isolated data, policy, secrets, and
lifecycle management:

```bash
bash runner/harness.sh start
bash runner/harness.sh status
bash runner/harness.sh shisad status
bash runner/harness.sh stop
```

See [`runner/README.md`](runner/README.md) and
[`runner/RUNBOOK.md`](runner/RUNBOOK.md).

## How changes are developed

For non-trivial work:

1. Define the behavior and its limits.
2. Identify the affected files and nearest user journey.
3. Write or update tests before implementation.
4. Make the smallest implementation that satisfies the behavior.
5. Validate the affected scope.
6. Update human-facing documentation when behavior, setup, security claims, or
   operational limits changed.

Security changes need both a blocked-risk case and a normal success case.
Changes that affect planner, tool, policy, channel, or runtime behavior should
also exercise the nearest representative end-to-end journey.

## Validation

Use the smallest test selection that proves the change. A broader successful
run replaces contained selections in the same environment; do not rerun them
only to collect another green result.

Typical localized change:

```bash
uv run --python 3.12 pytest tests/unit/test_example.py -q
uv run ruff check src/shisad/example.py tests/unit/test_example.py
uv run mypy src/shisad/example.py
```

When a shared security/runtime contract can change, also run the nearest
behavioral journey and the first-principles gate:

```bash
uv run --python 3.12 pytest tests/behavioral/test_first_principles_gates.py -q
```

Full coverage, supported-platform, packaging, and live-model runs are release
or agreed checkpoint work rather than defaults for every patch. The maintainer
release procedure is in [`docs/PUBLISH.md`](docs/PUBLISH.md).

## Public documentation boundary

Everything committed as documentation in this public repository must be
written for a human reader. Appropriate public documentation includes:

- product overview and usage;
- installation and operator procedures;
- configuration and API references;
- security architecture, threat model, and explicit limitations;
- architectural decision records and research analysis;
- contributor and maintainer procedures;
- release history in `CHANGELOG.md`.

Do not commit internal execution material here, including:

- milestone implementation plans or private roadmaps;
- worklogs, punchlists, review-lane traces, or release-decision ledgers;
- agent memory, session-specific agent instructions, or resumption notes;
- private repository paths, identifiers, model assignments, or governance
  records.

Public issues and pull requests may describe concrete public work. Future
product planning, internal implementation sequencing, and agent instructions
belong outside this repository.

Stable contributor instructions and developer tooling can remain public when
they help external developers work with shisad. They must not contain private
execution history or notes from a particular agent session.

### Documentation style

- Do not invent internal jargon, acronyms, labels, or abstract terms. Use
  established ordinary language and define necessary domain terms on first
  use. Temporary issue, review, and workflow labels are not product vocabulary.
- Lead with what the reader can do or observe.
- Link to the canonical detailed guide instead of copying its contents into
  README.
- Avoid internal milestone IDs and acceptance-test language.
- Keep version/status claims aligned with published artifacts.
- Preserve important platform, security, and recovery limitations while
  simplifying prose.
- Use "you" or "user" in end-user guides; use "operator" only when it names a
  distinct deployment or policy role.

## Git and pull requests

- Keep commits atomic and use conventional prefixes such as `feat:`, `fix:`,
  `docs:`, `test:`, `refactor:`, and `security:`.
- Do not add co-author footers generated by tools.
- Stage only the files intended for the commit and review the staged diff.
- Preserve external contributor credit. Maintainers may add focused fixup
  commits when a contribution needs security, quality, or documentation work.
- Pull requests should explain user-visible behavior, security implications,
  validation performed, and any known limitation.

## Reporting security issues

Follow [`docs/SECURITY.md`](docs/SECURITY.md) for private vulnerability reporting. Do not
publish credentials, exploit details, or sensitive logs in a public issue.
