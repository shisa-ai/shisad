# Memory Evaluations

shisad has two memory measurement paths:

- `shisad memory benchmark` is an in-repo deterministic smoke benchmark. Use it
  for quick local diagnostics and regression checks.
- MELT is the external memory evaluation runner. Use it for reproducible
  standard benchmark runs and MELT-native lifecycle smoke suites.

The two paths answer different questions. The built-in benchmark checks whether
the local memory stack can ingest, retrieve, and report diagnostic metrics in a
controlled synthetic fixture. MELT drives shisad as a System Under Test (SUT)
through the public `shisad memory sut` JSON Lines (JSONL) protocol and records
a methodology envelope, report schema version, per-case traces, and aggregate
metrics.

## Quick Smoke

Run the built-in shisad smoke benchmark from the shisad checkout:

```bash
uv run shisad memory benchmark --json
```

Useful options:

- `--fixture FILE` runs an external JSON benchmark fixture instead of the
  built-in synthetic smoke.
- `--limit N` changes the retrieval limit per question.
- `--fail-under-accuracy`, `--fail-under-recall`,
  `--fail-over-harm-rate`, and `--fail-over-p95-latency-ms` make the command
  fail when local thresholds are not met.

This command is not a MELT report and should not be compared to standard
benchmark scores.

## MELT Runs

Run MELT from the MELT checkout:

```bash
uv run melt run --sut fake --suite smoke --fixture smoke --output-dir results
uv run melt run --sut fake --suite lifecycle --fixture smoke --top-k 3 --output-dir results
```

To run the lifecycle smoke suite against shisad:

```bash
uv run melt run \
  --sut shisad \
  --sut-command "uv --directory /path/to/shisad run shisad memory sut" \
  --suite lifecycle \
  --fixture smoke \
  --top-k 3 \
  --output-dir results
```

MELT writes a summary at:

```text
results/<suite>_<sut>_<timestamp>_<config-hash>_<invocation>/summary.json
```

Per-run reports are under:

```text
results/<suite>_<sut>_<timestamp>_<config-hash>_<invocation>/runs/run-*/report.json
```

## Standard Benchmarks

LongMemEval is the primary static-conversation benchmark target. Full runs
require a local dataset file; MELT does not vendor restricted external
datasets.

```bash
uv run melt run \
  --sut shisad \
  --sut-command "uv --directory /path/to/shisad run shisad memory sut" \
  --suite longmemeval \
  --variant S \
  --fixture external \
  --split dev \
  --dataset-path /path/to/longmemeval.json \
  --top-k 5 \
  --runs 1 \
  --output-dir results
```

LoCoMo is a secondary directional signal. Category 5 is excluded by default
because the dataset audit records corrupted or ambiguous cases; including it
requires explicit opt-in and is reported as a caveat.

```bash
uv run melt run \
  --sut shisad \
  --sut-command "uv --directory /path/to/shisad run shisad memory sut" \
  --suite locomo \
  --fixture external \
  --split dev \
  --dataset-path /path/to/locomo.json \
  --audit-catalog-path /path/to/locomo-audit.json \
  --top-k 5 \
  --runs 1 \
  --output-dir results
```

Smoke fixtures are useful for checking the runner and SUT wiring. They are not
substitutes for full benchmark datasets.

## Lifecycle Suites

MELT-native lifecycle smoke suites cover memory behaviors that static
conversation benchmarks usually miss:

- Raw-event write quality.
- Structured correction and contradiction handling.
- Consolidation and decay.
- Core-memory stability.
- Multi-hop recall across sessions.
- Abstention when the system should not know.

Lifecycle reports include `write_surface` tags so raw-event write-quality
cases are not conflated with structured-memory setup cases. For shisad, current
lifecycle smoke support exercises the shipped SUT command and deterministic
memory maintenance path; it does not claim that shisad has been tuned to improve
benchmark scores.

## Report Envelope

Every MELT report records the fields needed to interpret a result:

- Suite id, suite version, fixture id, fixture hash, and split.
- SUT id, SUT version, SUT commit, and SUT contract version.
- MELT runner commit.
- Embedding provider/model identity or deterministic fallback.
- Judge identity, prompt hash, canary false-positive rate, or `deterministic`.
- `top_k`, bypass warnings, runs, seed, timestamp, and hardware metadata when
  available.
- Separate metrics for retrieval, answer quality, judged accuracy, abstention,
  lifecycle assertions, and raw-verbatim baselines.

MELT derives `preliminary` versus `final` from the split and run count. A
`final` result requires `--split held_out`, at least five runs, and methodology
validation; every other non-error report is `preliminary`. Fixture choice does
not by itself force `preliminary`, so smoke fixtures should still be described
as smoke checks even when they are used to exercise the held-out/five-run status
path.

## Non-Claims

v0.7.4 makes shisad measurable; it does not publish leaderboard claims by
itself. Do not treat smoke artifacts as final benchmark results, do not compare
R@k to answer accuracy, and do not treat baseline-adapter setup blockers as
shisad runtime failures. If an evaluation exposes a product bug, fix it with
regression coverage or record an explicit deferral before making a release
claim.

See also:

- [MELT SUT contract](memory-eval-sut-contract.md)
- [Roadmap](ROADMAP.md)
