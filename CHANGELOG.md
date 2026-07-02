# Changelog

All notable changes to shisad are documented in this file.

This changelog is release-oriented: a new section is added when preparing or
cutting a release tag. Pre-publish release content is marked explicitly and is
left unlinked until the tag exists. There is no standing "Unreleased" section.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Normal releases use semver-style versions; beta checkpoints and exceptional
follow-up patch lines may use PEP 440-compatible prerelease or four-segment
versions when the release checklist records that choice.

## [0.8.0] - 2026-07-02

This stable v0.8.0 release turns the beta authorization fixes into the
command-channel approval and UX-overhaul foundation.

### Added

- **Themeable terminal and web surfaces.** shisad now ships a shared theme
  foundation with built-in dark, light, and high-contrast palettes, imports
  common btop color themes, and applies consistent styling across the chat TUI,
  dashboard, and web view. Choose a theme with `SHISAD_UI_THEME` or point at a
  custom file with `SHISAD_UI_THEME_PATH`.

- **Refreshed chat TUI.** Chat sessions get new chrome with clearer status,
  styled evidence references, and status that refreshes from structured session
  state, including channel and user metadata as the session evolves.

- **Structured plan-step and task panels in the TUI.** The TUI surfaces the
  agent's active plan steps and the task snapshot for the current session as
  first-class panels that update as steps and tasks change. Stale plan-step
  rows are cleared on session teardown, and task snapshots stay bound to the
  session that owns them.

- **Task list inspection is scriptable.** `shisad task list` now reports an
  explicit empty state, and `shisad task list --json` prints raw scheduler
  metadata for local diagnostics. JSON output can include user-authored task
  text, schedule metadata, delivery-channel display fields, and identifiers, so
  redact it before sharing logs.

- **Polished dashboard tables.** The dashboard clarifies channel status and
  inactive states so you can see at a glance which channels are connected,
  idle, or unconfigured.

- **UI motion fallback.** Progress indicators and animated elements degrade
  gracefully on terminals without full motion support, and UI glyph selection
  respects locale precedence.

- **Command-channel approvals are no longer CLI-only for routine actions.**
  Discord-originated routine approvals advertise native Approve/Reject handling
  with CLI fallback, and TOTP prompts can stay on the originating trusted
  channel when it supports them.

- **Terminal fallback rendering is covered as an explicit contract.** Basic
  terminal and TUI pending-action text stays plain, ANSI-free, and includes
  approve, reject, preview, and warning details, so TOTP fallback paths remain
  usable on any terminal.

### Changed

- **The command channel is the preferred approval surface.** Approvals and TOTP
  prompts prefer the channel that issued the command, falling back to CLI only
  when the originating channel cannot handle the interaction. Where the channel
  supports it, TOTP is preferred over less-suitable channel methods. The
  chosen-channel principle is now spelled out in the design philosophy.

- **Approval capability advertising is honest.** Pending approvals only offer
  factors that are actually available for that row: expired rows suppress their
  affordances, unavailable WebAuthn routes are not offered, and channel-bound
  user identities are checked through the approval path. If no suitable factor
  is available, approval fails closed instead of pointing at an unusable prompt.

### Fixed

- **Discord approval and TOTP flows are more robust.** Discord approvals recover
  from missing modal fields, no-components responses, and defer paths without
  losing TOTP guidance; fenced or preview-formatted confirmations parse
  correctly; and unsupported inline chat approvals no longer appear on channels
  that cannot handle them.

- **Task and plan snapshots survive session lifecycle events.** Task snapshots
  are bound to the current session and daemon state so a restored session keeps
  its tasks; session teardown consistently clears plan steps through shared
  cleanup; and the task surface falls back safely when structured data is
  unavailable.

- **Session and planner identity binding is consistent.** CLI, helper, and
  session reject paths bind to the correct user identity, and planner resolve
  fallbacks pick the right one.

- **Coding-agent sessions honor the configured model override.** Agent Client
  Protocol coding-agent sessions default to the configured model override so
  model negotiation works consistently.

- **UI themes fail safely.** Broken, empty, or undecodable theme files fall
  back to the selected built-in palette instead of crashing or silently loading
  an unrelated default.

## [0.8.0b1] - 2026-06-25

This beta checkpoint follows `0.8.0b0` and keeps the release line focused on
reviewed bug fixes before the stable `v0.8.0` UX overhaul.

### Fixed

- **Structured turn authorization replaces prose goal matching.** The runtime
  no longer rejects high-risk tool proposals because the user goal lacked a
  hardcoded side-effect verb, and the tainted-side-effect LLM intent authorizer
  is replaced by structural current-turn anchoring for self-contained operator
  commands. Non-self-contained mixed-evidence side effects still route to
  confirmation or block paths. ([#85](https://github.com/shisa-ai/shisad/issues/85))

- **Ledger and explicit shell command requests reach clear execution paths.**
  The Ledger shell demo now queues confirmation with valid command-token atoms,
  and explicit shell command sequences such as `journalctl --disk-usage` reach
  pending confirmation, clear resolver denial, or policy denial paths instead
  of internal planner-validation messages.
  ([#61](https://github.com/shisa-ai/shisad/issues/61),
  [#77](https://github.com/shisa-ai/shisad/issues/77))

- **Read-only browser actions keep the no-confirmation path for authorized
  destinations.** The monitor cleanup preserves direct execution for
  read-mostly browser tools such as navigate/read/screenshot/end-session while
  known-bad argument content and non-browser suspicious HTTP destinations remain
  flagged.

- **Channel pending state is scoped by delivery target.** Channel chat now keeps
  active pending ids, visible pending rows, planner transcript context,
  continuations, and summarizer batching/cursors scoped to the current delivery
  target. Durable memory recall remains scoped by owner/workspace rather than
  channel target.

- **Planner validation recovery is clearer.** Recovered planner tool-call
  validation failures and unknown-tool remediation now preserve actionable
  responses without collapsing into confusing generic validation errors.

## [0.8.0b0] - 2026-06-25

This is a beta checkpoint before the stable `v0.8.0` UX overhaul. It publishes
the reviewed post-`v0.7.4` bug-fix stack so users can install a current build
while the larger v0.8 polish work continues.

### Added

- **Storage diagnostics now report SQLite FTS5 readiness.** `shisad doctor`
  can report whether the Python SQLite runtime has FTS5 enabled, and the docs
  explain install options for common environments. shisad also falls back when
  FTS5 is unavailable instead of crashing at daemon startup.
  ([#57](https://github.com/shisa-ai/shisad/issues/57),
  [#83](https://github.com/shisa-ai/shisad/issues/83))

- **Ledger remote-host setup is documented.** The Ledger bridge docs now show
  the supported topology for a remote shisad daemon with USB hardware attached
  to a local workstation. ([#76](https://github.com/shisa-ai/shisad/issues/76))

### Changed

- **Setup and web-search docs are more actionable.** Local source checkouts no
  longer require root-owned socket paths or custom environment setup for the
  normal development flow, and the SearxNG/web-search setup docs and
  unconfigured-backend messages now explain what to do next.
  ([#50](https://github.com/shisa-ai/shisad/issues/50),
  [#52](https://github.com/shisa-ai/shisad/issues/52),
  [#53](https://github.com/shisa-ai/shisad/issues/53))

- **Runtime environment examples avoid shell-quoting traps.** Runbook guidance
  now recommends comma-separated `runtime.env` values where bash-sourced
  JSON-array examples can lose quotes. ([#43](https://github.com/shisa-ai/shisad/issues/43))

### Fixed

- **Chat reconnects restore usable session history.** Reconnecting to an
  existing chat session now replays prior messages instead of starting with a
  blank view, including bounded transcript reads and retryable async blob
  backfills. ([#65](https://github.com/shisa-ai/shisad/issues/65))

- **Chat rendering handles common Markdown shapes.** Markdown headings render
  as block-level sections instead of running into the previous line, and
  Unicode bullet lists no longer collapse following prose into the final list
  item. ([#66](https://github.com/shisa-ai/shisad/issues/66),
  [#67](https://github.com/shisa-ai/shisad/issues/67))

- **The chat TUI handles session ids more safely.** Chat sends now recover or
  reject invalid session ids instead of calling `session.message` with missing
  or invalid identifiers. ([#68](https://github.com/shisa-ai/shisad/issues/68))

- **Reminder and time flows are less brittle.** One-shot reminders no longer
  display like recurring interval schedules, active TUI sessions can receive
  reminder notifications more reliably, direct reminder requests avoid false
  taint/cross-thread warnings, direct reminder listing is no longer vetoed by
  the sequence analyzer, and simple current-time requests can answer without
  a shell fallback loop. ([#49](https://github.com/shisa-ai/shisad/issues/49),
  [#54](https://github.com/shisa-ai/shisad/issues/54),
  [#58](https://github.com/shisa-ai/shisad/issues/58),
  [#59](https://github.com/shisa-ai/shisad/issues/59),
  [#60](https://github.com/shisa-ai/shisad/issues/60))

- **Direct local file and audit requests work through clearer policy paths.**
  Direct local document reads and read-only audit queries no longer fall into
  misleading taint or goal-misalignment dead ends.
  ([#51](https://github.com/shisa-ai/shisad/issues/51),
  [#55](https://github.com/shisa-ai/shisad/issues/55))

- **Browser and evidence-result failures are clearer.** Browser subprocess
  failures preserve useful sanitized details in audit/CLI output, Ubuntu
  default Node 18 setups avoid the undici WASM sandbox failure mode, and
  post-tool synthesis after `evidence.read` reaches the user instead of
  stopping at planner intent prose.
  ([#44](https://github.com/shisa-ai/shisad/issues/44),
  [#45](https://github.com/shisa-ai/shisad/issues/45),
  [#46](https://github.com/shisa-ai/shisad/issues/46))

- **Channel confirmations and cooldowns are less fragile.** Slack in-channel
  `confirm N` / `reject N` syntax is recognized, and confirming an action no
  longer trips a cooldown because a different session recently confirmed
  another action. ([#41](https://github.com/shisa-ai/shisad/issues/41),
  [#42](https://github.com/shisa-ai/shisad/issues/42))

- **MCP tool execution reaches the control plane with the right action kind.**
  Chat-proposed MCP tool calls are no longer blocked as unknown control-plane
  actions before normal policy evaluation. ([#82](https://github.com/shisa-ai/shisad/issues/82))

- **Policy blocks return a clearer denial.** When policy blocks a tool action,
  the response now surfaces the denial and reason instead of hedging or
  entering another clarification loop. ([#84](https://github.com/shisa-ai/shisad/issues/84))

- **The development implement self-check handles external directories.** The
  implement self-check no longer reports a false negative when an agent writes
  to an external directory outside the shisad git repo. ([#80](https://github.com/shisa-ai/shisad/issues/80))

### Security

- **Release dependency audit blockers were remediated.** The release lock now
  resolves patched versions of `aiohttp`, `cryptography`,
  `pydantic-settings`, `pyjwt`, `python-multipart`, `starlette`, and `torch`,
  and the `cryptography` runtime dependency range now targets the patched 48.x
  line.

- **Ledger signer registration rejects corrupted or wrong public keys.**
  Ledger signer setup now fails fast when a public-key file is not valid PEM,
  uses the wrong key type, uses the wrong elliptic curve, or requests an
  unsupported Ledger algorithm/signing-scheme combination. The Ledger key
  extraction docs also avoid redirecting interactive `npx` prompts into PEM
  output. ([#75](https://github.com/shisa-ai/shisad/issues/75))

## [0.7.4] - 2026-05-21

### Added

- **Memory evaluations can run outside shisad.** MELT (Memory Evaluation for
  Lifecycle Testing) is the external runner for standard memory benchmarks and
  lifecycle smoke suites, so shisad's memory system can be measured without
  importing shisad's internals.

- **A public memory evaluation command exposes shisad for benchmarking.**
  `shisad memory sut` speaks a versioned JSON Lines protocol over stdio, with
  run-scoped directories, deterministic time control, structured memory
  writes, consolidation, historical queries with explicit time bounds, and
  structured error responses. The handshake declares which capabilities the
  system supports and which embedding model, storage backend, and
  consolidation behavior is in effect, so reports faithfully describe what was
  measured.

- **Lifecycle memory smoke suites cover behavior static benchmarks miss.**
  The first MELT lifecycle fixture checks raw-event write quality, structured
  correction and contradiction handling, consolidation and decay, core-memory
  stability, multi-hop recall across sessions, and abstention.

- **Baseline adapter targets fail with setup guidance.** MELT registers
  Memobase, memv, MIRA-OSS, and Karta as known future adapter targets; selecting
  one without the needed service, package, dataset, or wrapper now explains the
  missing setup instead of looking like an unknown adapter name.

### Changed

- **Memory benchmark docs distinguish smoke diagnostics from evaluations.**
  Public docs now explain when to use `shisad memory benchmark`, when to use
  MELT, how to reproduce smoke runs, which report fields matter, and why
  smoke artifacts should be interpreted separately from held-out, multi-run
  benchmark claims.

- **Changelog entries link public issues and pull requests.** Entries
  referencing publicly tracked work now link the GitHub issue or PR number
  inline, so users can follow a change back to its public discussion. Earlier
  entries with clear public provenance were updated to the same convention.

### Fixed

- **Memory queries see the full historical record.** Queries against
  structured memory now search the full as-of history and preserve link,
  conflict, decay, and supersession metadata at the time being asked about, so
  an evaluation that asks what shisad believed at an earlier point sees the
  relationships that existed then rather than today's resolved view.

- **Memory evaluation answer results echo the originating query id.** When the
  evaluation command returns an answer result, the response now carries back
  the query id the question was asked under, so external runners can match
  answers to their questions unambiguously.

### Security

- **Provider URLs no longer leak secrets in error messages.** When a provider
  URL is malformed or fails to load, error messages and metadata redact secret
  literals embedded in path, fragment, query, and delimiter forms, including
  URL-encoded and decoded variants, so credentials accidentally pasted into
  provider configuration do not surface in logs or evaluation reports.

- **Memory evaluation runs are owner-scoped and fail closed on missing
  dependencies.** The evaluation command rejects queries that cross owner
  boundaries, sanitizes provider metadata in evaluation responses, and fails
  closed when embeddings are required but not configured, so a misconfigured
  run cannot silently produce results from another owner's data or an
  unintended fallback.

## 0.7.3.1 Release Content - 2026-05-16

### Changed

- **The browser tool understands more of how real web pages work.** Form
  submission now handles explicit submit buttons, fragment-only submits,
  fieldset-disabled controls, dialog submits, form-associated submitters
  defined outside the form they target, and Enter-to-submit. Hidden,
  opacity-hidden, and visibility-overridden fields are filtered out of the
  browser snapshot the agent sees, so it works from what a person would
  actually see on the page. Repeated submissions and drifted GET query strings
  are rejected instead of replaying through.

- **Page titles stay metadata, not content.** Browser screenshots and web
  fetches no longer surface the page's title as part of the answer body unless
  you explicitly ask for the title. When screenshot OCR text is available,
  shisad prefers the visible page content over the title, and confirmed
  page-title metadata is preserved as a separate block in confirmation
  summaries.

- **Web search recovers when evidence is weak.** When search results do not
  actually answer your question, shisad explains what was found, what is
  missing, and falls back to the search recovery path instead of synthesizing a
  confident-sounding wrong answer. Reservation markers in fetched pages are
  extracted from both English and Japanese phrasing, including split or negated
  forms. ([#27](https://github.com/shisa-ai/shisad/issues/27), [#28](https://github.com/shisa-ai/shisad/issues/28))

- **Short confirmation cooldowns retry instead of dead-ending.** If you
  resolve a confirmation while a short cooldown is still active, shisad waits
  through the cooldown and retries once. Longer cooldowns still surface as
  `cooldown_active` so you know to wait. ([#35](https://github.com/shisa-ai/shisad/issues/35))

- **Confirmed fetch follow-ups summarize instead of leaking raw evidence.**
  When you ask a follow-up after confirming a web fetch, the planner now sees a
  summarized version of the fetched content rather than the raw reservation
  markers, while still treating fetched page content as untrusted.

- **Blocked malformed URLs explain what to do next.** When the output firewall
  blocks a malformed URL, the response now tells you to provide a trusted URL
  or ask shisad to search, instead of returning an opaque blocked message.
  ([#22](https://github.com/shisa-ai/shisad/issues/22))

- **Planner fallback errors explain which route was used.** When a provider
  route fails over to a fallback, the resulting message explains which route
  was used and why, so you can tell whether the answer came from your preferred
  provider. ([#38](https://github.com/shisa-ai/shisad/issues/38))

### Fixed

- **Browser snapshots preserve editable boundaries.** Empty editable blocks,
  repeated line breaks, nested editable regions, and rich-text replays keep
  their visible structure as you walk through forms, instead of collapsing or
  duplicating boundaries. Noneditable labels and editable placeholder breaks
  are filtered out of the snapshot so the agent does not mistake them for
  user-entered text.

- **Browser launchers find their runtime dependencies.** When a compatible
  browser wrapper path is configured, wrapper scripts, env-style launchers,
  interpreter code flags, and hermetic runtime paths are mounted into the
  browser sandbox, so launching the browser from a non-standard install path
  works without manual configuration. ([#25](https://github.com/shisa-ai/shisad/issues/25), [#26](https://github.com/shisa-ai/shisad/issues/26), [PR #32](https://github.com/shisa-ai/shisad/pull/32))

- **Confirmed navigation prefers task-specific destinations.** Confirmed
  navigation retries from the URL the task asked for, validates same-origin
  candidates, and normalizes default ports before comparing destinations, so a
  generic fallback URL no longer wins over the destination you actually
  requested. ([#29](https://github.com/shisa-ai/shisad/issues/29), [#30](https://github.com/shisa-ai/shisad/issues/30))

- **Browser confirmations bind to the canonical destination.** Allowlist
  confirmation, pending policy aliases, page title replay aliases, and
  confirmation tool aliases are canonicalized before they enter the session, so
  confirmation answers stay attached to the destination you approved.
  ([#37](https://github.com/shisa-ai/shisad/issues/37))

### Security

- **Sensitive browser fields are precleared and kept out of replay.** When
  the agent fills a sensitive form field, the field is precleared before reuse,
  snapshot replay skips sensitive values, and stale or help-only browser
  wrappers are rejected before they can replay sensitive state. Diagnostic
  output from the browser sandbox is kept separate from the main session so it
  cannot leak field values back into the transcript.

- **Recovery after lockdown ignores forged prompt text.** Lockdown recovery
  notices, memory summaries, and resume prompts strip forged or
  evidence-attributed prompt text before the planner sees them. Imported
  recovery prompts that lack a verified terminal context are rejected instead
  of being replayed, so a poisoned archive cannot smuggle a recovery
  instruction past the lockdown gate. ([#31](https://github.com/shisa-ai/shisad/issues/31))

- **Filesystem paths in output are preserved when readable, redacted when
  secret-shaped.** The output firewall distinguishes source-shaped filesystem
  paths, which stay visible so you can act on them, from high-entropy path
  segments that look like secrets, which are redacted. Browser file URLs,
  Windows paths, drive-scheme paths, and spaced file URLs are redacted
  consistently, including their delimiter variants, while readable source paths
  in tool diagnostics survive unchanged. ([#34](https://github.com/shisa-ai/shisad/issues/34))

- **PII and pending-confirmation redaction are bounded.** URL path redaction,
  output secret replacement, and PII redaction have explicit bounds, so a
  pathological input cannot exhaust the redaction pass and let secrets through.
  Sensitive pending text, approval metadata digests, and cleanroom proposals
  are redacted before they reach the trace or transcript.

- **Episode and destination attribution stay within bounds.** Historical
  destination anchors, episode attribution, and carry-forward attribution honor
  the bounds of the current session, so an older episode cannot smuggle a
  destination claim into a new task.

## [0.7.3] - 2026-05-09

### Added

- **Search your saved history by time.** You can now ask the assistant about
  your own memory timeline using fuzzy phrases like "last Thursday" or "a
  couple weeks ago", and get results back in chronological order. Timeline
  results stay within your authorized visibility and still go through the
  usual redaction before surfacing; fuzzy phrases that cannot be resolved are
  reported as unresolved instead of silently expanding.

- **Pick a topic back up across sessions.** When you resume a conversation,
  shisad can carry forward relevant thread context from prior sessions so you
  do not have to re-explain where you left off. Resume is scoped to your
  threads, honors the same visibility rules as normal recall, and matches
  thread identifiers exactly instead of by prefix.

- **Inspect and manage conversation threads.** New CLI and API commands let
  you list threads, see why a thread was selected, and filter by session
  scope, so you can audit how cross-session context is being applied to the
  conversation you are in.

- **Timeline and thread inspection output is local operational data.** JSON
  and terminal output from the new timeline/thread commands can include local
  history snippets, thread identifiers, channel binding values, and owner or
  workspace identifiers after redaction. Anyone who can read that terminal,
  file, or API response can read the scoped output. `memory.timeline.promote`
  writes selected rows back through the usual memory write gates.

- **See which threads are getting attention.** Thread packet activity now
  surfaces through review and metrics commands so you can tell which packets
  are active, which are deferred, and why, in a stable priority order.

- **Capture reusable procedures from what you did.** When the assistant walks
  through a multi-step procedure, it can now propose a procedure-experience
  candidate that you review, approve, or reject before it joins your reusable
  memory. Candidates stay scoped to you and require explicit promotion before
  they are reused.

### Changed

- **Imported archive rows use conservative labels and provenance.** When
  older session archives are loaded, imported timeline rows use generic tool
  labels and conservative provenance until a later write path re-confirms
  them, so legacy data cannot claim richer trust than it earned. Existing
  archive imports keep the original owner scope instead of being re-attributed
  on restore.

### Fixed

- **Confirmed replies and promoted evidence reach the channel you asked
  for.** Confirmation flows, supplemental evidence delivery, and promoted
  evidence paths now preserve the original delivery target instead of falling
  back to a generic session channel. Resumed coding-agent sessions also keep
  their connector binding so follow-ups return to the same channel.

- **Archived transcripts keep the owner that actually wrote them.** Archive
  import and transcript-backed session rebuilds preserve the original owner
  scope, so imported history is attributed correctly in later searches.

### Security

- **Forged archive checkpoints and session bindings are rejected.** Archive
  checkpoint sessions, session delivery bindings, and checkpoint session
  bindings fail closed when they carry forged or malformed metadata, so a
  poisoned archive import cannot impersonate other sessions, redirect
  delivery, or smuggle cross-session identifiers into your timeline.

- **Timeline answers honor owner scope, publication policy, and
  redaction.** Timeline search and read paths enforce private/shared
  visibility, apply publication policy before shared/public responses, and
  invalidate timeline entries whose earlier redaction would otherwise leak
  through a new answer. Fuzzy phrase continuations and malformed anchors are
  rejected instead of being expanded past the window you asked about.

- **Imported timeline labels and provenance are sanitized.** Tool labels,
  provenance strings, and session identifiers on imported timeline rows are
  sanitized before they enter the index, so a malicious archive cannot carry
  forged labels or foreign session identifiers into your timeline.

- **Procedure-memory candidates require a verified owner and explicit
  approval.** Procedure-experience candidates, promotion packets, ingest
  artifacts, and the review queue fail closed without a verified owner scope.
  Legacy rows are surfaced for preview instead of being silently backfilled,
  unsafe stored targets are rejected, and approval packets are bound to the
  candidate they approve, so a candidate cannot be promoted or reused without
  explicit review.

- **Scanner verdicts and procedure keys reject malformed input.** Queue
  scanner verdicts, findings, and summaries, along with procedure candidate
  keys, reject blank, malformed, and control-character input instead of
  normalizing it through, so a malformed scan report cannot be coaxed into an
  approval.

- **Ledger bridge transitive `uuid` advisory closed.** The optional Ledger
  bridge now pins `uuid@11.1.1` through an npm override, closing the carried
  supply-chain exception for `GHSA-w5hq-g745-h8pq`.

## [0.7.2] - 2026-05-07

### Added

- **Recall can tell you when it does not have enough to answer.** When you ask
  the assistant about saved notes and the available entries do not cover the
  question, recall can report what it found, what is missing, and expand to
  related entries up to the configured limit instead of answering from partial
  context. Client requests can also cap how much expansion is allowed.

- **Audit queries support machine-readable output.** `shisad audit query` now
  accepts a JSON output mode alongside the default human-readable table, which
  makes it easier to script inspection of audit records. JSON output can include
  local audit metadata and tool arguments after the usual redaction, so handle
  it like other local audit-log output.

- **A memory benchmark command is available for evaluating recall quality.**
  You can run a fixture-driven benchmark against your local memory to measure
  recall precision, latency, and stage metrics. The optional JSON report is
  intended for local evaluation records and may reflect the fixture prompts you
  provide. Invalid fixtures and bad paths now fail with a clear error instead
  of a traceback.

### Changed

- **Memory listing, review, and promotion require a workspace scope.** CLI and
  API calls that list personal memory, approve or reject remembered entries,
  promote entries between private and shared collections, or maintain aliased
  notes and todos now require an explicit user and workspace scope. Operations
  without that scope fail closed so memory maintenance cannot accidentally
  touch another workspace's entries.

- **Debug restart reports what actually happened.** Restart and refresh
  commands now report the resolved daemon status and path, whether the
  refreshed process came back up, and any failure details, so you can tell a
  successful restart apart from a silent failure.

- **Memory auto-extraction stays off when you disable it.** When auto
  extraction is turned off in configuration, the assistant no longer backfills
  memory from past sessions on startup or writes derived extraction artifacts.

### Fixed

- **Blocked assistant replies explain themselves inline.** When a reply is
  blocked by policy, including for secret echoing, a disallowed URL, or a
  malformed URL, the notice includes a plain-language reason inline, and the
  original payload is redacted from audit records instead of being stored
  verbatim.

- **Coding-agent sessions recover from transport hiccups.** The coding-agent
  bridge preserves transport error details so problems are diagnosable, cleans
  up greeting replies so they match the rest of the conversation, and keeps the
  fallback greeting scoped to genuine fallbacks only.

- **Policy-denied tool calls are traced with the right reason.** When a tool
  call is denied, the denial reason is preserved through the trace and
  observation path with the correct precedence instead of being overwritten by
  a later rejection, so audit records reflect why the action was actually
  blocked.

- **Cross-workspace identifier conflicts no longer produce false positives.**
  Identifier-conflict checks now respect owner and workspace scope, so notes
  that share an identifier across unrelated workspaces do not get flagged as
  conflicting with each other.

- **Filesystem scope rejections surface back to you.** When a file tool rejects
  a path that falls outside the configured workspace scope, the reason is
  returned to the chat and CLI instead of being swallowed.

### Security

- **API tokens, credentials, and key material are redacted everywhere errors
  and diagnostics surface.** Error messages, tool diagnostics, and audit records
  redact authorization headers, bearer tokens, API keys, key material,
  human-readable secret labels, and multi-line credentials, including across
  escaped JSON containers, compact multi-line containers, and malformed
  containers that previously let values slip through. Malformed secret
  containers now fail closed instead of being forwarded.

- **The coding-agent bridge scrubs secrets from serialized transport
  payloads.** Plural and human-readable secret labels, multi-value secrets, and
  serialized transport messages are redacted before they reach logs or session
  replay, so credentials pasted into coding-agent sessions do not leak through
  transport errors or replay paths.

- **Feedback and channel reactions do not replay across retired sessions.**
  Legacy reaction rows are migrated forward and orphaned feedback is retired,
  so reactions tied to old sessions or retired channel sides can no longer be
  replayed to influence trust, memory, or confirmation decisions in current
  sessions. Derived memory telemetry from these signals is now bounded.

- **Memory review rejects operations without a verified user scope.**
  Attempting to approve, reject, promote, or modify remembered entries without
  a user/workspace scope fails closed instead of defaulting to an unowned
  bucket, so review actions cannot accidentally touch entries attributed to
  another user.

- **Unowned memory promotion and public-retrieve flows honor provenance.**
  Public retrieval no longer exposes entries whose provenance is private, and
  superseding a closed workflow entry no longer reopens it, so shared recall
  surfaces cannot be coaxed into returning private or retired content.

## [0.7.1] - 2026-04-30

### Added

- **Recover from a caution-level lockdown without leaving chat.** When shisad
  enters a recoverable lockdown after suspicious activity, the notice explains
  how to resume from either chat or the command-line interface (CLI), and you
  can ask the assistant to resume the session directly.

- **Check pending actions and lockdown state from the CLI.** Run
  `shisad action list` to see actions waiting on your confirmation, and
  `shisad lockdown status` to see the current lockdown level, reason, and
  session context without digging through audit logs. Machine-readable output
  can include pending-action details and tool arguments from your local shisad,
  so treat that output as operational data.

### Changed

- **Published releases now include supply-chain evidence.** The release
  workflow builds and checks both distribution artifacts, uploads a software
  bill of materials (SBOM), records attestations that tie packages back to the
  source release, and continues to publish to the Python Package Index (PyPI)
  from the release tag through GitHub's keyless trusted publishing.

### Fixed

- **Chat renders Markdown properly.** Assistant replies now display formatted
  Markdown instead of showing the raw punctuation, and the chat entry box wraps
  longer prompts, grows while you type, and collapses after you send.

- **Confirmed actions show their results and stay in the conversation.**
  Approving a pending action returns the tool output, the confirmation reply
  includes a summary of the result, and follow-up turns can use that result
  instead of re-queuing the same action.

- **Personal notes and remembered context stay usable in chat.** Trusted CLI
  searches no longer require confirmation just because earlier recall contained
  untrusted content, notes you save with the `remember` command can be written
  and verified reliably, statements you make in the current session are treated
  as your own trusted input, and cross-session notes and identity memory are
  available to the assistant through the usual recall paths.

- **Confirmation and multi-tool cleanup are more forgiving.** A single pending
  confirmation now accepts `confirm` or `go ahead` even when earlier context is
  untrusted, confirmed replies are labeled as the result of a confirmed action
  rather than a generic tool output, explicit trusted `todo` writes in
  multi-tool turns can proceed based on the current request, and default
  workspace listings correctly handle common phrases like "this folder" or
  "the folder".

- **Trusted chat keeps working while a confirmation is pending.** You can keep
  chatting while an action is waiting for approval, and clear confirmation or
  rejection replies are handled through the same approval flow as other CLI
  confirmations.

- **Natural file lookups go to the right tools.** Follow-ups like
  "can you look for the file?" now use the filesystem browsing and read tools
  rather than falling back to shell commands.

- **File discovery and shell searches stay inside the active workspace.**
  Shell-based file searches run from the configured workspace, block disguised
  commands and attempts to escape the workspace, preserve common file-finding
  phrasing, and route unknown or risky targets to confirmation with the exact
  command shown for review.

- **Audit and startup output makes it clear which runtime you are inspecting.**
  `shisad audit query` and `shisad audit verify` show the active data
  directory, and startup checks accept `ANTHROPIC_API_KEY` and report Anthropic
  keys separately from `OPENAI_API_KEY`.

- **The Codex coding-agent bridge installs without prompting.** First-run
  Codex sessions no longer stall on an interactive adapter-install prompt.

- **Malformed browser URLs are rejected before any network call.** Ambiguous or
  malformed hostnames are caught up front instead of reaching the browser or
  network layer.

- **Chat replies are cleaner on recovery paths.** Explicit memory questions can
  use saved notes when needed, suspicious pasted content is summarized safely,
  and user-requested Markdown-formatted URLs no longer trigger spurious
  confirmation markers. Confirmation replies and suspicious-paste summaries
  also avoid unnecessary system narration.

### Security

- **Personal memory is scoped per user and workspace.** Long-term memory writes
  and recall are tied to the user and workspace that created them, so personal
  notes and identity memory from one workspace do not leak into another.
  Recall, export, and retrieval now reject missing user or workspace
  information instead of silently returning private rows, while shared entries
  remain available where intended.

- **Your own personal recall is treated as trusted context when clean.** The
  assistant no longer treats your own prior-session memory from the same user
  and workspace as untrusted just because it was recalled later, while
  untrusted content or content from other users and workspaces continues to be
  handled as untrusted.

- **Warnings about cross-session content are less noisy.** The check now looks
  only at recent text you wrote instead of comparing against unrelated
  sessions, reducing false positives without expanding what can authorize
  actions.

## [0.7.0] - 2026-04-25

### Added

- **Structured long-term memory now has separate surfaces for identity, active
  work, recall, reusable skills, and evidence.** The assistant can keep
  user-approved identity and preference memory available across sessions, track
  active threads and waiting-on items, surface explicit source reads, and
  expose reusable skills without mixing those surfaces together.

- **The assistant can propose new memories and ask you to confirm them before
  they become trusted memory.** Identity candidates, strong memory updates,
  and queued skill suggestions now stay in review flows until you approve them
  from a trusted context instead of silently entering live recall or
  invocation.

- **A derived knowledge graph and consolidation pass are available through the
  live control surface.** Shisad can query and export the current graph view,
  detect strong updates, flag contradictions, and record auditable merge,
  quarantine, and confirmation events without turning the graph into
  authoritative state.

### Changed

- **Memory now lives in a local SQLite backend with versioned entries and audit
  events.** Existing memory callers keep the same public recall interface, but
  the storage layer now records typed entry metadata, trust fields, review
  state, workflow state, supersede history, and explicit ingress handles.

- **Recall and active context are filtered more aggressively by trust, scope,
  and workflow state.** Pending-review items stay out of normal recall,
  identity only accepts trusted approved entries, and active-attention content
  stays separate from the trusted metadata that selects it.

### Security

- **Every memory write records its ingress handle and trust tier.** When you
  inspect a memory entry you can see whether it came from a trusted command,
  an untrusted external channel, a tool result, or a consolidation pass, and
  untrusted sources cannot silently write into elevated memory surfaces.

- **Pending-review memories and skills stay out of default recall and
  invocation paths.** Unconfirmed writes from public channels, external
  content, or tool output no longer leak into trusted memory, active identity,
  or skill invocation until you promote them explicitly.

- **Consolidation can suggest changes but cannot silently promote trust.**
  Duplicate cleanup, contradiction tracking, archive/quarantine decisions, and
  strong-update proposals all remain auditable low-trust events until a user
  confirmation path stamps the promoted result.

- **The Ledger bridge's transitive `axios` lock now resolves to `1.15.2`.** The
  `contrib/ledger-bridge/` lockfile previously resolved `axios@1.13.5` through
  `@ledgerhq/*`, which is affected by CVE-2025-62718 (`NO_PROXY` hostname
  normalization bypass → SSRF) and CVE-2026-40175 (CRLF header injection →
  IMDSv2 bypass when combined with prototype pollution). The bridge now uses an
  npm `overrides` entry to require `axios@^1.15.2`; the committed lockfile
  resolves that range to `axios@1.15.2` and `proxy-from-env@2.1.0`.

## [0.6.7.1] - 2026-04-23

### Fixed

- **Ledger Nano X now round-trips on Linux.** On Linux, the bridge was
  sometimes picking the Nano X's FIDO/U2F HID interface instead of the
  APDU interface, which made the first transaction request hang. The
  bridge now filters Ledger HID interfaces by their APDU usage page on
  Linux, matching what Ledger's own transport already does on macOS and
  Windows. Stax and Flex users were not affected — those models only
  expose the APDU interface.

[0.6.7.1]: https://github.com/shisa-ai/shisad/compare/v0.6.7...v0.6.7.1

## [0.6.7] - 2026-04-21

### Added

- **See and approve transactions on compatible Ledger displays.**
  When a compatible Ledger signer key is registered, shisad can send
  the transaction to the device over the local USB bridge service and
  wait for you to read it on the Ledger's screen and physically
  confirm. Because the display and confirm button are on the hardware,
  a compromised host can't change what you're approving behind the
  scenes.
  - Configure with `SHISAD_SIGNER_LEDGER_URL` and register the key
    with `shisad signer register --backend ledger`.
  - Ledger is the first hardware device on shisad's generic
    trusted-display signer interface. The same interface (a local
    HTTP bridge that shisad signs against) already backs the KMS
    (Key Management Service) signer and is the path for adding other
    hardware wallets later.
  - `v0.6.7` ships before a maintainer-validated device and firmware
    compatibility matrix; that follow-up is tracked for `v0.6.7.1`.

### Security

- **Ledger approvals step down when the device can't show you what
  you're signing.** If the Ledger reports blind-signing mode or an
  unreadable transaction, shisad treats the approval as lower-trust
  instead of claiming you verified it on the hardware screen.

### Fixed

- **Peer-credential enforcement works on macOS.** When shisad runs on
  macOS, the daemon's Unix-socket peer check previously used a
  Linux-only syscall, so it couldn't read the uid or pid of clients
  connecting to the daemon. The daemon now uses the Darwin
  peer-credential syscalls instead.

- **Public docs and CHANGELOG now address end-users as "user", not "operator".**
  The README, CHANGELOG, 2FA guide, env-var reference, and other
  user-facing docs were inconsistent about how they addressed the
  reader. "Operator" still appears in deployment, admin, runbook, and
  threat-model docs where it names a distinct role. Prior CHANGELOG
  sections were also updated so readers don't hit the old term when
  scanning release history — the `[X.Y.Z]` sections on `main` now
  differ slightly from the frozen GitHub Release notes at each tag.

Thanks @GuitareCiel from Ledger for contributing shisad's first external pull
request.

## [0.6.6] - 2026-04-19

### Added

- **Image and voice recordings can be sent as attachments.** The daemon
  ingests local attachment paths with size caps and format validation, so
  large or malformed files are rejected cleanly before reaching the planner.

- **Read and search local email through the assistant.** A new
  MsgVault-backed email toolkit lets the assistant search configured local
  mail archives and read individual messages. When you configure
  `SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST`, requests are scoped to granted accounts
  before reaching the archive.

- **Discord public channels now have per-channel policies.** Configure whether
  shisad chats, reads along quietly, or stays passive in each public channel,
  while public-channel sessions exclude owner-private conversation context.

- **`SOUL.md` customizes the assistant's persona.** Put `SOUL.md` in the
  user config path and the planner layers it in as trusted persona
  preferences below safety and developer instructions. Updates go through a
  dedicated admin edit path from a clean session, so injected content cannot
  rewrite persona mid-conversation.

### Security

- **Attachment ingest is bounded and validated.** Uploads hit size limits
  before decoding, audio ID3 tags are validated, and malformed files are
  quarantined rather than passed on.

- **Email reads validate local message IDs before reading.** MsgVault tools
  resolve message IDs against email metadata and compare IDs exactly before
  reading the matched archive record. When
  `SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST` is set, reads also use that account
  resolution; when MsgVault is disabled, email reads are refused outright.

- **Discord DMs stay fail-closed.** Direct messages require an explicit trust
  grant; granting access to a public channel does not implicitly open DMs.

- **`SOUL.md` edits run from a clean admin session.** Persona updates are
  proposed from a fresh context rather than replaying the current conversation,
  and they go through a narrow admin path rather than general filesystem
  writes. Project-specific facts are steered toward the memory system instead
  of being silently appended to persona text.

### Fixed

- **Tool-only turns no longer go silent.** When a turn runs tools but produces
  no assistant text, shisad synthesizes a short summary of what ran so you can
  see what happened instead of getting an empty reply.

- **Follow-up turns keep same-session evidence.** Evidence refs from previous
  tool-backed turns are carried forward in the same session, so a follow-up can
  use the source envelope behind earlier results instead of relying only on a
  prose recap.

## [0.6.5] - 2026-04-17

### Added

- **External tool servers can connect via the Model Context Protocol (MCP).**
  Configure one or more MCP servers — stdio subprocesses or HTTP endpoints —
  through `SHISAD_MCP_SERVERS`, and the daemon discovers their tools at
  startup. Discovered tools appear in sessions as `mcp.<server>.<tool>` and
  work like built-in tools. If a configured server is unreachable, the daemon
  continues without it.

- **External agents can send signed requests over socket or HTTP.** A new A2A
  listener accepts Ed25519-signed requests from registered remote agents,
  verifies identity and intent, and routes accepted work into a session.
  Operators define which agents can connect and what they can ask for.
  Configure via `SHISAD_A2A`.

- **`shisad a2a keygen` generates an identity keypair.** Run it once to
  create the Ed25519 keys the daemon needs for A2A signing and verification.
  The command prints the public-key fingerprint for out-of-band exchange with
  remote operators.

- **`shisad restart --fresh-config` reloads environment on restart.** Changed
  environment variables take effect immediately instead of requiring a manual
  stop-then-start cycle. The prior configuration is saved as an owner-only
  snapshot before the reload; that backup can contain secrets and should be
  handled accordingly.

### Security

- **MCP tools require confirmation by default.** Unless a server appears in
  `SHISAD_MCP_TRUSTED_SERVERS`, every tool call from that server asks for
  your approval before executing. Trusted servers skip the prompt, but
  their outputs are still treated as external input for screening purposes.

- **MCP tool definitions are validated before registration.** Parameter names,
  types, enum values, and descriptions are screened for injection patterns at
  startup. Tools that fail validation are rejected. Subprocess-based MCP
  servers launch with a sanitized environment allowlist instead of inheriting
  the daemon's full environment by default, but they are not sandboxed and
  still run with the daemon's OS privileges.

- **A2A requests are cryptographically verified.** Every inbound request must
  carry a valid Ed25519 signature matching the agent's registered public-key
  fingerprint. Unsigned envelopes, signature mismatches, and replayed messages
  are rejected.

- **A2A access is fail-closed.** Each remote agent can only send requests for
  intents you have explicitly allowed. Omitting the allowlist means
  zero access until you add grants. Per-agent rate limits (default
  60/min, 600/hour) are enforced on the verified cryptographic identity to
  limit repeated abuse.

- **Every A2A ingress decision is audited.** Accepted requests, rejections,
  and rate-limit violations emit structured audit events with sender identity,
  intent, outcome, and reason.

### Changed

- **Startup logs show resolved configuration.** The daemon now logs which
  capabilities are active at startup — web search, web fetch, filesystem
  roots, backend URL — so misconfigurations surface immediately instead of at
  first tool call.

- **Operator docs cover MCP and A2A setup.** `docs/DEPLOY.md` and
  `docs/ENV-VARS.md` include configuration examples and trust-model
  explanations for both new interoperability features.

## [0.6.4] - 2026-04-13

### Security

- **Prompt-injection screening now runs through one scanner.** The daemon
  firewall and the analyzer path now share `textguard` for structural
  detection, so the same prompt-injection checks apply across both surfaces
  instead of drifting between separate implementations.
- **Hidden-text and encoded-input detection is broader.** The new scanner
  brings deeper decode coverage and stronger unicode normalization while
  shisad keeps the split-base64 and legacy analyzer compatibility shims it
  still needs for existing workflows.
- **Runtime rule sourcing is simpler and harder to drift.** The daemon
  validates textguard's bundled YARA backend at startup and no longer ships a
  second copied local rule set.

### Changed

- **PromptGuard stays optional.** Base installs now include `textguard[yara]`,
  while local PromptGuard runtime checks remain opt-in through the
  `security-runtime` dependency group for source checkouts or the
  `shisad[promptguard]` extra for package installs.
- **Operator status reflects bundled-rule provenance explicitly.**
  `daemon.status` now reports that the old local security-asset copy is gone
  and that the runtime is using bundled rules.

## [0.6.3] - 2026-04-12

### Added

- **Pending approvals now show what to do next.** When an action needs your
  approval, you see a preview of what it wants to do and the exact commands to
  approve or reject it.
- **TOTP approvals work from chat.** You can enter a TOTP code in the same
  conversation instead of switching to the SSH CLI.
- **TOTP enrollment shows a scannable QR code.** The CLI renders a QR code
  when possible and still prints the raw `otpauth://` URI as a fallback.
- **Anthropic provider preset.** Setting `ANTHROPIC_API_KEY` now configures
  planner and monitor routes without accidentally enabling an incompatible
  embeddings route.

### Fixed

- **Creating todos, notes, and reminders from the CLI no longer asks for
  unnecessary confirmation.** When PromptGuard content safety was enabled, its
  injection-detection score consistently came back slightly above zero on
  direct user input, which caused the system to treat even simple user
  commands like "create a todo" as needing approval. The content safety
  classifier now skips the neural-net check on direct user input — the user is
  the trust root, not an attack surface. Pattern-based detection still runs
  for telemetry.
- **Confirmation replies no longer create new actions.** Typing `confirm 1`,
  `y`, `yes`, a bare number, or `reject` is now recognized as a command
  instead of being sent to the planner as a new request.
- **Stale pending actions are cleaned up on restart.** Old pending rows that
  lost their approval envelope or were locked out of their confirmation method
  no longer keep appearing in the pending list.
- **Terminal replies keep readable line breaks.** Markdown-style responses no
  longer collapse into a single hard-to-read line.
- **Missing model configuration gives useful guidance.** When no language
  model is configured, the error message tells you what to set up instead of
  echoing a fake response.

### Changed

- **Startup and doctor output are more helpful.** `shisad doctor` works
  without a subcommand, missing filesystem roots or embeddings routes are
  easier to spot, overridden presets are labeled as custom, and missing chat
  dependencies point to the `shisad[chat]` install extra.
- **Tools shown to the planner match what's actually available.** When
  filesystem or git roots are not configured, those tools are no longer
  advertised to the planner as usable.

### Security

- **Delegated task scopes are fenced more tightly.** File paths, git refs,
  extensionless filenames, semantic IDs, and numeric chat-thread IDs now stay
  in their correct resource scope instead of accidentally authorizing a
  different kind of resource.
- **CLI convenience skips only low-risk internal bookkeeping.** Creating notes,
  todos, and reminders from a clean CLI session skips the confirmation prompt,
  but suspicious content, untrusted session history, external side effects, and
  stronger policy requirements still go through normal approval.

## [0.6.2] - 2026-04-09

### Added

- **Sensitive actions can require stronger approvals.** Operators can now step
  up from the original software confirmation prompt to TOTP re-auth,
  WebAuthn/passkeys, local-helper approvals, or signer-backed authorization
  depending on policy and risk.
- **Private and SSH-only deployments can approve actions without bouncing to a
  browser.** `shisad-approver` adds a local helper path for stronger approval
  flows on locked-down hosts.
- **There is now a dedicated end-user 2FA guide.** `docs/2FA.md` explains the
  shipped TOTP setup and confirmation experience in plain user-facing terms.

### Security

- **Approval decisions are bound to the exact action the user reviewed.** The
  daemon now records stronger approval metadata, explicit fallback rules, and
  replay-resistant approval/signer evidence in the audit trail.
- **Evidence blobs can be encrypted at rest when an external artifact-KMS is
  configured.** Stored blob bytes stop being plaintext on disk, recoverable
  refs stay available for later recovery, and `evidence.read` /
  `evidence.promote` still work through the live runtime.
- **Signer-backed approvals are verified locally against registered public
  keys.** The daemon no longer has to trust a remote signer service's summary
  of what was approved.

### Changed

- **Public docs now match the shipped v0.6.2 trust model.** The roadmap,
  deployment docs, and user docs now reflect what is actually shipped in
  the approval/key-boundary lane and what remains follow-on work.

## [0.6.1] - 2026-04-05

### Security

- **Security analysis runs in a separate process from the main daemon.** If
  one is compromised, the other is not directly reachable.
- **ML-based injection screening for untrusted content.** Tool arguments and
  untrusted inputs now pass through a PromptGuard 2 classifier before the
  agent can act on them.
- **Unicode-steganography detection works in the shipped build.** The YARA
  rule for hidden-character detection was broken in prior releases due to a
  build issue; it now compiles and runs correctly.
- **You get alerts when denied actions repeat.** When the daemon denies
  a suspicious action (e.g., an unexpected capability request or outbound
  connection), it now logs structured details and warns you once the
  pattern crosses a configurable threshold — previously these were silently
  dropped.
- **Tool actions are checked against what the user actually asked for.** Before
  executing a tool, the runtime verifies the action traces back to the user's
  request. Reads without a clear link are routed to user confirmation; writes
  without a clear link are blocked.
- **Subtasks can inherit their parent session's approved scope.** When a parent
  session is still clean, delegated subtasks reuse its approved resource scope
  instead of requiring re-confirmation for every file access.
- **Modified skill tools are rejected with an explanation.** If a skill's tools
  have changed since they were last reviewed, the daemon logs why the tool was
  dropped instead of silently ignoring it.

### Changed

- **Changelog now follows end-user-facing style guidelines.** See
  `docs/PUBLISH.md` for the principles; the short version is: plainly state
  how functionality has changed, not how it's built internally.

## [0.6.0] - 2026-04-03

### Added

- **Multi-step task orchestration.** The agent can now delegate work to
  separate task sessions with safe data handoffs, result validation, and
  credential scoping — a long-running task can't leak context or credentials
  back to the main session.
- **Session migration and archival.** Sessions survive daemon restarts with
  their security state intact, and completed sessions can be exported/imported
  with integrity checks.
- **Artifact tracking with approval history.** Delegated task outputs are
  tracked in a structured ledger that records who approved what and when.
- **Web search tool** (`web.search`) for querying the web from within a
  session (requires a configured search backend).
- **Web fetch tool** (`web.fetch`) for retrieving web pages, with content
  stored as evidence references to keep large untrusted payloads out of the
  main conversation context.
- **Browser automation tools**: `browser.navigate`, `browser.read_page`,
  `browser.screenshot`, `browser.click`, `browser.type_text`, and
  `browser.end_session` for interacting with web pages directly (requires
  `SHISAD_BROWSER_ENABLED=1` and a configured browser command).
- **Web content rendered as text in the terminal** — fetched pages and browser
  reads display as readable text rather than raw HTML.
- **Skill tool integrity checks.** Local skill tools are validated against
  persisted schema hashes — modified or revoked tools are rejected at runtime.
- **Hardened release pipeline.** Releases now use PyPI OIDC trusted publishing
  with SBOM generation and provenance attestations.
  - Dependency-review and zizmor CI gates added.
  - GitHub Actions pinned to SHA digests.
  - `SHISAD_REQUIRE_LOCAL_ADAPTERS` env var locks down runtime adapter
    downloads.

### Security

- **Browser writes require user confirmation** and are scoped to the approved
  page context.
- **Hardened browser isolation is on by default.** Wildcard browser scope
  entries are rejected because they can't be safely enforced.
- **Evidence references persist across restarts and sessions**, keeping large
  untrusted content out of the main conversation context by default.
- **Skill authorization rejects modified or revoked artifacts** at runtime;
  dynamic remote tool discovery remains out of scope for this release line.

### Changed

- Updated public docs (`ROADMAP.md`, `TOOL-STATUS.md`) to reflect actual
  browser and web tool status after the v0.6.0 release.

## [0.5.2] - 2026-04-01

### Fixed

- Added project URL links to `pyproject.toml` so PyPI shows links to the
  GitHub repo, issues, and changelog.
- Added `license` field (Apache-2.0) to `pyproject.toml`.

## [0.5.1] - 2026-04-01

### Added

- **Automatic API key fallback.** If `SHISA_API_KEY` is not set, shisad
  auto-detects `ANTHROPIC_API_KEY`, reducing first-run friction.
- Supply-chain dependency audit map (`docs/AUDIT-supply-chain.md`).
- `CHANGELOG.md` and release checklist (`docs/PUBLISH.md`).
- First PyPI publication to claim the `shisad` package name.

### Security

- Tightened dependency pinning and CI install controls (hash-verified installs,
  stricter version bounds).

### Fixed

- Version string in `__init__.py` synced to match `pyproject.toml` (was stuck
  at 0.3.4).

## [0.5.0] - 2026-03-30

Initial public release.

### Highlights

- **Security-first agent framework** with per-call policy enforcement — every
  tool call is checked against the security policy before execution.
- **Sandbox execution** with namespace isolation, filesystem jails, and
  fail-closed runtime guards.
- **Hot-reloadable skills and plugins** managed by the control plane.
- **Multi-layer security** covering auth, egress auditing, supply-chain
  hardening, multi-encoding injection defense, and adversarial gates.
- **Structured memory** with semantic search.
- **Audit trails** and anomaly detection, with training-ready LLM trace
  recording.
- **End-to-end demo** script and runner harness for live verification.

[0.8.0]: https://github.com/shisa-ai/shisad/compare/v0.8.0b1...v0.8.0
[0.8.0b1]: https://github.com/shisa-ai/shisad/compare/v0.8.0b0...v0.8.0b1
[0.8.0b0]: https://github.com/shisa-ai/shisad/compare/v0.7.4...v0.8.0b0
[0.7.4]: https://github.com/shisa-ai/shisad/compare/v0.7.3.1...v0.7.4
[0.7.3]: https://github.com/shisa-ai/shisad/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/shisa-ai/shisad/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/shisa-ai/shisad/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/shisa-ai/shisad/compare/v0.6.7...v0.7.0
[0.6.7]: https://github.com/shisa-ai/shisad/compare/v0.6.6...v0.6.7
[0.6.6]: https://github.com/shisa-ai/shisad/compare/v0.6.5...v0.6.6
[0.6.5]: https://github.com/shisa-ai/shisad/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/shisa-ai/shisad/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/shisa-ai/shisad/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/shisa-ai/shisad/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/shisa-ai/shisad/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/shisa-ai/shisad/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/shisa-ai/shisad/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/shisa-ai/shisad/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/shisa-ai/shisad/releases/tag/v0.5.0
