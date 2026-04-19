# Attachment Ingest MVP

*Status: v0.6.6 scoped baseline*

## Scope

The first attachment slice is a local, read-only ingest primitive for images and
voice recordings. It does not implement Discord download plumbing, email
attachment export, OCR, provider-specific speech-to-text, arbitrary document
parsing, outbound attachments, or multimodal model input.

The runtime surface is `attachment.ingest`. It accepts an allowlisted local file
path, optional declared MIME type, optional display filename, and optional
caller-supplied transcript text for voice recordings. It returns a bounded
manifest and an ArtifactLedger evidence reference when the file can be safely
classified or quarantined.

## Threat Model

Attachments are untrusted content. The risks are:

- Parser and decoder bugs in rich media formats.
- Extension/MIME spoofing that routes a hostile file through the wrong parser.
- Hidden image text or audio transcript instructions that try to steer the
  planner.
- Large files that exhaust memory, disk, or provider budget.
- Quarantined data being silently reintroduced through `evidence.read`.

## Runtime Contract

`attachment.ingest` must:

- Read only files under `SHISAD_ASSISTANT_FS_ROOTS`, with PEP resource checks
  applying to the `path` argument.
- Enforce byte limits before parsing.
- Classify supported images and voice recordings by magic/header bytes, not by
  extension alone.
- Parse only bounded headers for metadata such as image dimensions or WAV
  duration; it must not decode pixels or execute media codecs in this MVP.
- Treat transcripts as untrusted text and screen them with the ContentFirewall
  before storing them.
- Store a tainted JSON manifest in ArtifactLedger, not raw attachment bytes.
- Mark unsupported, malformed, oversized, or transcript-risky media as
  `quarantined` with a reason code.
- Prevent default `evidence.read` and `evidence.promote` access to quarantined
  manifests.

## Deferrals

OCR, STT provider calls, channel attachment downloads, email attachment export,
PDFs/documents, and multimodal model input remain follow-on work. External STT
or vision providers are egress surfaces and need separate credential, policy,
and taint contracts before they can ship.

