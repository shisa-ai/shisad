# shisad Memory Eval SUT Contract

`shisad memory sut` exposes shisad's memory subsystem as a MELT System Under
Test (SUT). It runs `MemoryManager`, `IngestionPipeline`, and
`ConsolidationWorker` in-process. The daemon is not started.

The SUT command is an evaluation surface, not the interactive assistant
surface. MELT owns benchmark orchestration and report generation; shisad owns a
stable black-box command that MELT can invoke without importing shisad internals.

## Stability

- Current contract version: `b2`.
- Transport and operation names are part of the public SUT contract for
  v0.7.4 evaluation artifacts.
- Metadata fields that describe shisad internals are reported as facts about
  the reference SUT, not as requirements for every future SUT.
- New capabilities should be added through capability negotiation rather than
  by changing existing operation semantics.

## Transport

- Transport: JSON Lines over stdio.
- One request object produces one response object.
- Structured operation errors are returned on stdout with `ok: false`.
- Fatal process startup failures may exit non-zero. A normal `shutdown` exits
  zero after `shutdown_ack`.
- Stderr is reserved for process logs and diagnostics; MELT stores it as an
  artifact and does not parse it as protocol data.

## Handshake

The first non-empty message must be `hello`:

```json
{
  "op": "hello",
  "contract_version": "b2",
  "run": {"run_id": "run-001", "seed": 42},
  "owner": {"user_id": "melt-user", "workspace_id": "melt-workspace"},
  "paths": {
    "state_dir": "/tmp/melt/state",
    "config_dir": "/tmp/melt/config",
    "artifact_dir": "/tmp/melt/artifacts"
  },
  "capabilities_requested": [
    "reset",
    "time_control",
    "consolidation",
    "query_as_of",
    "structured_memory_write",
    "answer_generation"
  ],
  "config_overrides": {"embedding_mode": "deterministic"}
}
```

`hello_ack` returns shisad identity, accepted/rejected overrides, supported and
unsupported capabilities, and `envelope_metadata`. It echoes the accepted
`contract_version`; MELT treats a mismatch as a protocol error. The
`capabilities_supported` and `capabilities_unsupported` arrays are an
order-preserving exact partition of `capabilities_requested`: every requested
capability appears exactly once in one of the two arrays, and unrequested
capabilities are omitted from the handshake. Public metadata fields must not
contain endpoint credentials; provider base URLs are reported without userinfo,
query strings, or fragments. MELT also applies report redaction before copying
SUT metadata into report artifacts.
Provider-backed protocol errors redact the configured API key and URL secrets
before they are emitted.

Capability vocabulary:

- Hard capabilities supported by shisad: `reset`, `time_control`,
  `consolidation`, `query_as_of`, `structured_memory_write`.
- Soft capability currently unsupported by shisad: `answer_generation`.

Embedding overrides:

- `embedding_mode="deterministic"` uses the local SHA-256 fallback and no API
  keys.
- `embedding_mode="provider"` accepts `embedding_base_url`,
  `embedding_api_key`, and `embedding_model_id` for an OpenAI-compatible
  embeddings endpoint. Provider mode fails closed on provider embedding errors
  instead of falling back to deterministic vectors, and public fingerprints are
  derived from the public provider identity rather than from secret-bearing URL
  text.

## Isolation and Resources

MELT supplies run-local `state_dir`, `config_dir`, and `artifact_dir` paths in
the handshake. shisad stores evaluation state under those paths for the current
run and does not use the daemon's normal runtime data directory.

`reset` clears only the configured SUT `state_dir` contents and rebuilds memory
components for the next case. It must not delete arbitrary filesystem paths,
global shisad state, or MELT output artifacts.

MELT enforces adapter-level timeouts. shisad returns structured errors for
recoverable protocol and operation failures; fatal startup failures may exit
non-zero. Provider-backed embedding failures in provider mode fail closed rather
than silently switching to deterministic embeddings.

## Operations

- `metadata`: returns identity, contract version, capabilities, and envelope
  metadata.
- `reset`: clears only the configured `state_dir` contents, rebuilds memory
  components, and returns `reset_ack.run_id` matching the request.
- `ingest`: writes raw event content to retrieval storage. Response `ack`
  includes MELT `event_id`, SUT `source_id`, `chunk_id`, and `created_at`.
- `memory_write`: writes structured lifecycle setup memory through
  `MemoryManager.write_with_provenance`. Response `memory_write_ack` includes
  `entry_id`, `source_id`, and `created_at`.
- `consolidate` / `tick`: runs deterministic consolidation once and returns
  `consolidate_ack` / `tick_ack`.
- `query`: returns evidence-first retrieval results plus scoped structured
  memory evidence in `query_result`, with `query_id` matching the request.
  Structured memory evidence includes
  `metadata.decay_score` so lifecycle suites can test decay after
  consolidation. When structured relationships are present, metadata may also
  include `supersedes`, `supersedes_source_id`, `conflict_entry_ids`, and
  `conflict_source_ids`. shisad reports supersession on the successor evidence;
  it does not emit `superseded_by` metadata because current queries suppress
  superseded entries and historical queries suppress future successors. For
  `query_as_of`, entry evidence and relationship metadata are scoped to the
  query cutoff; future successors or contradictions are not emitted for
  historical queries. `answer` is empty unless `answer_generation` is
  supported.
- `answer`: returns `answer_result` with `unsupported_capability` while shisad
  declares `answer_generation` unsupported.
- `shutdown`: returns `shutdown_ack` and terminates the loop.

All operations may include `timestamp` as an ISO-8601 timestamp. shisad maps it
to `created_at` for `ingest`/`memory_write`, `now` for `consolidate`/`tick`,
and `as_of` for `query`.

## Fail-Closed Cases

The SUT returns structured errors for:

- Unsupported `contract_version`.
- Missing or partial owner scope.
- Malformed JSON or non-object messages.
- Unknown capabilities or operations.
- Invalid timestamps, source types, paths, or required fields.

Operation errors do not poison the session. MELT may continue issuing
operations after a structured error, or it may stop the current run according to
runner policy.

## Running Through MELT

From the MELT checkout, a local shisad lifecycle smoke run uses the public SUT
command:

```bash
uv run melt run \
  --sut shisad \
  --sut-command "uv --directory /path/to/shisad run shisad memory sut" \
  --suite lifecycle \
  --fixture smoke \
  --top-k 3 \
  --output-dir results
```

See [Memory Evaluations](memory-evals.md) for standard benchmark commands,
report interpretation, and non-claims.
