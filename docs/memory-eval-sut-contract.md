# shisad Memory Eval SUT Contract

`shisad memory sut` exposes shisad's memory subsystem as a MELT System Under
Test (SUT). It runs `MemoryManager`, `IngestionPipeline`, and
`ConsolidationWorker` in-process. The daemon is not started.

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
  "run": {"run_id": "run-001", "case_id": "case-001", "seed": 42},
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
unsupported capabilities, and `envelope_metadata`. MELT copies
`envelope_metadata` verbatim into its report envelope under
`sut_envelope_metadata`.

Capability vocabulary:

- Hard capabilities supported by shisad: `reset`, `time_control`,
  `consolidation`, `query_as_of`, `structured_memory_write`.
- Soft capability currently unsupported by shisad: `answer_generation`.

Embedding overrides:

- `embedding_mode="deterministic"` uses the local SHA-256 fallback and no API
  keys.
- `embedding_mode="provider"` accepts `embedding_base_url`,
  `embedding_api_key`, and `embedding_model_id` for an OpenAI-compatible
  embeddings endpoint.

## Operations

- `metadata`: returns identity, contract version, capabilities, and envelope
  metadata.
- `reset`: clears only the configured `state_dir` contents and rebuilds memory
  components.
- `ingest`: writes raw event content to retrieval storage. Response `ack`
  includes MELT `event_id`, SUT `source_id`, `chunk_id`, and `created_at`.
- `memory_write`: writes structured lifecycle setup memory through
  `MemoryManager.write_with_provenance`. Response includes `entry_id`,
  `source_id`, and `created_at`.
- `consolidate` / `tick`: runs deterministic consolidation once.
- `query`: returns evidence-first retrieval results plus scoped structured
  memory evidence. `answer` is empty unless `answer_generation` is supported.
- `answer`: returns `unsupported_capability` while shisad declares
  `answer_generation` unsupported.
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
