# Publishing Checklist

Use this as the release checklist for cutting a new `shisad` version.

Scope:

- Use this checklist whenever preparing a new Git tag or publishing to PyPI.
- A checked-in Dockerfile is a local release candidate, not authorization to
  tag, push, sign, or claim a registry image. Container publication requires
  a separate explicit human decision and the controls below.
- `CHANGELOG.md` is release-oriented, not an in-progress ledger. Add a new
  topmost version section when cutting a release; do not keep an `Unreleased`
  section.
- If a release-close review needs changelog content before the tag/publish
  step is authorized, keep that temporary section unlinked as
  `## X.Y.Z Release Content - YYYY-MM-DD`. During the explicit release action,
  convert it to the standard linked release section in the commit that will be
  tagged.

## Versioning

Use semver-style bumps for normal releases:

- Patch (`0.5.1`): bug fixes, packaging/docs-only releases, low-risk UX
  improvements.
- Minor (`0.6.0`): new user-facing capabilities, commands, or significant
  security/runtime features.
- Beta/prerelease (`0.8.0b0`): checkpoint releases for installable bug-fix or
  release-candidate builds before a stable minor release. Treat them as
  PEP 440 prereleases and mark the GitHub Release as a prerelease.
- Major (`1.0.0`): intentionally breaking changes to CLI behavior, config
  format, or security model that need explicit upgrade guidance.

Exception: when the human lead intentionally opens a follow-up patch line on
top of an already published patch release, use a PEP 440-compatible
four-segment version such as `0.7.3.1`. Treat it as a patch release in scope
and validation, and call out the choice in the release-close evidence.

## Version Locations

Version must be updated in both places:

- `pyproject.toml` — `version = "X.Y.Z"`, an approved prerelease such as
  `version = "X.Y.ZbN"`, or an approved patch-line `version = "X.Y.Z.N"`
- `src/shisad/__init__.py` — `__version__ = "X.Y.Z"`, an approved prerelease
  such as `__version__ = "X.Y.ZbN"`, or an approved patch-line
  `__version__ = "X.Y.Z.N"`

## Release Punch List

- [ ] Start from a clean tree: `git status -sb`
- [ ] Sync with the remote release base:
      `git fetch --tags origin` and `git pull --ff-only`
- [ ] Pick the next version number and decide patch/minor/major
- [ ] Update version in `pyproject.toml`
- [ ] Update version in `src/shisad/__init__.py`
- [ ] Sync the lockfile: `uv lock`
- [ ] Update `CHANGELOG.md`:
      add a new topmost release section and update it for the current phase
      (see **CHANGELOG Style** below). Pre-tag release-close candidates use
      `## X.Y.Z Release Content - YYYY-MM-DD` (content-prep date) without a
      compare link; the explicit tag/publish action converts that heading to
      `## [X.Y.Z] - YYYY-MM-DD` (actual tag date — may be later than the
      content-prep date if release-close took multiple days), adds the
      bottom `[X.Y.Z]` comparison link in the commit that will be tagged, and
      includes standard public issue / pull-request references for every
      entry that maps to a public GitHub issue or PR.
- [ ] Review `README.md` thoroughly for release parity. The `README.md`
      tends to drift during long release lanes because contributors update
      other docs first. Verify:
      - The `## Status` section names the correct "latest published line"
        for the release you are cutting.
      - Pre-tag / "ReleaseClose in progress" / "about to be tagged" /
        "pre-tag release content" wording is removed.
      - The feature bullets in `## What makes shisad different`, the
        version/focus table, and any claims about current capabilities
        match what actually ships at the tag (no overclaiming future work
        as shipped).
      - Any version-string references in install or quick-start examples
        reflect the release being cut.
- [ ] Review top-level operator docs for release parity:
      `docs/ROADMAP.md`, `docs/ENV-VARS.md`, `docs/TOOL-STATUS.md`,
      `docs/USE-CASES.md`
- [ ] If release-close changes dependency resolutions or workflow/action pins,
      update `docs/AUDIT-supply-chain.md` in the same lane so the recorded
      package inventory and CI/release trust notes stay current. When any
      edit to this file happens during release-close, also update the
      `*Updated:*` header and the `*Snapshot basis:*` line so the doc's own
      metadata reflects the current release rather than a stale date.
- [ ] Update release-version/status tables while doing the docs parity pass:
      make sure the current release line is presented as current, prior
      releases are de-emphasized, and any version/focus tables stay in sync.
      Unless the doc explicitly needs patch-level detail, treat these tables as
      major release-line summaries and keep patch releases in `CHANGELOG.md`
- [ ] Update README/docs when install steps, CLI behavior, shipped tool
      surfaces, or the documented security model changed
- [ ] Run release validation:
      `uv run ruff format --check .`
- [ ] Run release validation:
      `uv run ruff check .`
- [ ] Run one primary Python 3.12 deterministic pass with coverage and marker
      reporting:
      `uv run --python 3.12 pytest tests/ -m "not requires_cap_net_admin" --cov=src --cov-report=term-missing --cov-report=xml -q -rxXs`
- [ ] Apply the global and per-module coverage gates to that same report:
      `uv run python scripts/coverage_baseline.py --xml coverage.xml` and
      `uv run python scripts/coverage_module_gate.py --xml coverage.xml --critical-floor 80 --module-floor 60`
- [ ] Confirm the contained adversarial, behavioral, and first-principles cases
      passed, with zero failed/xfailed/xpassed/skipped first-principles gates.
      Do not rerun those subsets after the full pass.
- [ ] Run one Python 3.13 compatibility pass without duplicate coverage:
      `uv run --python 3.13 pytest tests/ -m "not requires_cap_net_admin" -q -rxXs`
- [ ] Run the clean consumer-artifact lane without skips on Linux/amd64:
      `SHISAD_RUN_PACKAGING_TESTS=1 SHISAD_RUN_CONTAINER_TESTS=1 uv run --frozen --python 3.12 pytest tests/packaging/test_clean_artifact_journey.py -q -rxXs`
- [ ] Review the artifact supply-chain diff: `pyproject.toml`, `uv.lock`, the
      digest-pinned Docker `FROM` lines, Docker build context, runtime package
      set, fixed uid/gid, image env, namespace/pasta startup preflight, and
      absence of test/build tools and baked credentials.
- [ ] Record relevant macOS/Windows support checks for the exact candidate;
      reuse candidate-bound CI artifacts rather than rerunning them locally.
- [ ] Run live-model release gate:
      `bash live-behavior.sh --live-model -q`
- [ ] Run ACP live coding-agent gates (one pass per configured agent):
      `timeout 240s env SHISAD_LIVE_CODING_AGENTS=claude uv run pytest tests/live/test_coding_agents_live.py -q`
      `timeout 240s env SHISAD_LIVE_CODING_AGENTS=codex uv run pytest tests/live/test_coding_agents_live.py -q`
      `timeout 240s env SHISAD_LIVE_CODING_AGENTS=opencode uv run pytest tests/live/test_coding_agents_live.py -q`
- [ ] Run the live-model + ACP live lanes sequentially, not in parallel.
      The behavioral/live harnesses assume a lightly loaded local daemon
      startup path; overlapping them can create avoidable socket-startup
      timeouts and invalidate the release-close evidence.
- [ ] Record the exact release-close validation commands and outcomes in the
      active implementation/worklog doc; if any live lane cannot be run, note
      why before claiming the release is closeable
- [ ] Run the Discord `#shisad` publish gate with the current tree before
      claiming the release is publish-ready. See **Discord #shisad Publish
      Gate** below.
- [ ] Record the Discord publish-gate evidence in the active
      implementation/worklog doc: redacted command shape, environment posture,
      target channel, session/message identifiers or transcript/log path when
      available, and result.
- [ ] Stop before GitHub tag/PyPI publish if the current tree cannot post to
      Discord `#shisad`, unless the human lead records an explicit narrowed
      publish scope.
- [ ] Remove stale build artifacts:
      `rm -rf dist/`
- [ ] Build fresh artifacts:
      `uv build`
- [ ] Verify package metadata:
      `uvx --from twine twine check dist/*`
- [ ] Smoke-test the built wheel:
      `uv run --isolated --with dist/shisad-X.Y.Z-py3-none-any.whl shisad --help`
- [ ] If release notes or docs claim package-installed runtime assets outside
      `src/shisad`, verify those assets from the built wheel. Otherwise
      truth-scope the docs to source checkouts or operator-supplied paths.
- [ ] Stage only release files explicitly and review them:
      `git add ...`, `git diff --staged --name-only`, `git diff --staged`
- [ ] Commit release metadata:
      `git commit -m "chore: prepare vX.Y.Z release"`
- [ ] Create an annotated tag:
      `git tag -a vX.Y.Z -m "vX.Y.Z"`
- [ ] Push the release commit and tag:
      `git push origin main`, `git push origin vX.Y.Z`
- [ ] Publish via trusted publishing workflow (primary path):
      `gh -R shisa-ai/shisad workflow run "Publish to PyPI" -f tag=vX.Y.Z`
      (or: Actions > "Publish to PyPI" > Run workflow, enter `vX.Y.Z`).
      The build phase takes ~7 minutes (builds, runs tests, audits
      dependencies, verifies metadata, generates SBOM, creates attestations).
      The publish step requires confirmation before uploading to PyPI via OIDC.
- [ ] Create a GitHub Release from the tag:
      `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file -` (pipe the
      matching `CHANGELOG.md` section, or use `--notes "..."` inline)
- [ ] Attach SBOM to the GitHub Release:
      download `sbom-shisad-X.Y.Z` artifact from the workflow run, then
      `gh release upload vX.Y.Z sbom-shisad-X.Y.Z.spdx.json`
- [ ] Verify the published package:
      `uvx --refresh --from "shisad==X.Y.Z" shisad --help`
- [ ] For releases that expose the assistant profile, verify it from the
      published artifact too:
      `uvx --refresh --from "shisad[assistant]==X.Y.Z" shisad --help`
- [ ] Verify the GitHub Release, tag, and PyPI project page all show the new
      version
- [ ] Verify attestation is visible on the PyPI project page
- [ ] Do not describe the local Dockerfile candidate as an "official image"
      unless an explicitly authorized registry workflow has published it and
      the exact manifest digest, SBOM/provenance, signature/verification path,
      supported platform, and pull command have all been recorded. Otherwise
      keep public wording at "local container candidate."
- [ ] If GitHub code scanning raises new alerts on the release commit, triage
      them with `gh` before assuming manual UI work is required:
      `gh api '/repos/<owner>/<repo>/code-scanning/alerts?state=open&tool_name=CodeQL&per_page=100'`
      `gh api '/repos/<owner>/<repo>/code-scanning/alerts/<id>/instances'`
      After human review confirms a false positive or test-only hit, dismiss
      programmatically with:
      `gh api --method PATCH '/repos/<owner>/<repo>/code-scanning/alerts/<id>' -f state=dismissed -f dismissed_reason='false positive' -f dismissed_comment='...'`
      or `dismissed_reason='used in tests'` as appropriate. Record alert IDs
      and disposition in the active worklog when they affect release-close.
- [ ] Confirm the tree is clean: `git status -sb`

## Discord #shisad Publish Gate

Before a release is considered publish-ready, run the current shisad tree
against the configured Discord integration and confirm it can post a low-noise
test message or approved release announcement to Discord `#shisad`.

The gate must use shisad's runtime channel path, not a direct Discord API
client. One acceptable command shape is:

```bash
export RUNNER_INHERIT_SHISAD_ENV=1
export SHISAD_DATA_DIR=/tmp/shisad-release-data
export SHISAD_SOCKET_PATH=/tmp/shisad-release.sock
export SHISAD_POLICY_PATH=/tmp/shisad-release-policy.yaml

bash runner/harness.sh start --no-debug

uv run python - <<'PY'
import asyncio
import os
from pathlib import Path

from shisad.core.api.transport import ControlClient


async def main() -> None:
    socket_path = os.environ["SHISAD_SOCKET_PATH"]
    channel_id = os.environ["SHISAD_DISCORD_DEFAULT_CHANNEL_ID"]
    client = ControlClient(Path(socket_path))
    await client.connect()
    try:
        result = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "<allowlisted-release-user-id>",
                    "workspace_hint": "",
                    "reply_target": channel_id,
                    "content": (
                        "Reply with exactly the approved release announcement "
                        "or the approved low-noise publish-gate smoke text."
                    ),
                    "message_id": "release-publish-gate-vX.Y.Z",
                }
            },
        )
        delivery = dict(result.get("delivery", {}) or {})
        target = dict(delivery.get("target", {}) or {})
        if target.get("recipient"):
            target["recipient"] = "<Discord #shisad default channel id>"
        delivery["target"] = target
        print(
            {
                "delivery": delivery,
                "session_id": result.get("session_id", ""),
                "pending_confirmation_ids": result.get("pending_confirmation_ids", []),
            }
        )
    finally:
        await client.close()


asyncio.run(main())
PY

bash runner/harness.sh stop
```

Evidence must not print or paste bot tokens, webhook URLs, raw environment
dumps, or unredacted logs. Record only the secret-loading posture (for example,
which approved profile or secret loader was used), the target as
`Discord #shisad`, the command shape with secret values redacted, the session
or message identifier when available, and the result. If the post cannot be
completed, stop the publish process and record the blocker or the human lead's
explicit narrowed-scope rationale before any tag or PyPI publish action.

## CHANGELOG Style

The CHANGELOG is a user-facing document. Write it so someone who uses shisad
(but doesn't develop it) can understand what changed and why they should care.

### Pre-Tag Release Content

When release-close review happens before the human lead has authorized tagging
and publishing, use an unlinked topmost heading:

```markdown
## X.Y.Z Release Content - YYYY-MM-DD
```

Do not add a bottom `[X.Y.Z]` comparison link while the `vX.Y.Z` tag does not
exist. When the explicit release action starts, convert that heading to the
normal release form and add the compare link in the release commit that will
be tagged:

```markdown
## [X.Y.Z] - YYYY-MM-DD

[X.Y.Z]: https://github.com/shisa-ai/shisad/compare/vA.B.C...vX.Y.Z
```

### Post-Tag Stability

Once a `## [X.Y.Z]` section has been tagged and the GitHub Release is
created, treat that section as frozen. The `CHANGELOG.md [X.Y.Z]` section is
the notes for tag `vX.Y.Z`, and the GitHub Release text is a snapshot of
that section at release-create time. Editing `[X.Y.Z]` on `main` after the
tag makes `HEAD` and the shipped GitHub Release notes drift, which confuses
readers and breaks the invariant that the section describes the tagged
release. Fix-follow corrections belong in the next patch release, not in
the already-tagged section.

**Narrow exception: cross-section terminology sweeps.** If a
terminology change would make `main`'s CHANGELOG confusing to a new
reader scanning top-to-bottom (e.g., one term used in the latest
release, a different term in older sections), the sweep can be
applied to prior sections in the same commit. This breaks the
`HEAD`/Release-notes invariant for the rewritten sections, so
document the drift in the announcing release's CHANGELOG bullet and
keep the change terminology-only (no semantic edits). Do not use
this exception for content corrections — those still belong in a
follow-on patch release.

### Principles

1. **Lead with the end-user-visible effect, not the subsystem.**
   Start with what changed for the end-user: what is safer, easier,
   faster, clearer, or newly possible. If the bold lead starts with an
   internal component name, architecture term, or implementation mechanism,
   rewrite it.
   - Good: "Security analysis runs in a separate process from the main daemon."
   - Bad: "Control-plane analysis is isolated from the main daemon path."
   - Good: "Tool actions are checked against what the user actually asked for."
   - Bad: "Risky tool actions must trace back to committed intent."
   - Good: "Subtasks can inherit their parent session's approved scope."
   - Bad: "Delegated TASK work can inherit trusted scope from a clean COMMAND session."

2. **One feature per bullet.** If a bullet has commas separating five things,
   break it into five bullets.

3. **Write for an end-user who has not read our internals.**
   Assume the reader uses the software, but does not know our ADRs, milestone
   plan, or internal vocabulary. Avoid milestone IDs, component names, and
   compound-adjective chains. If a sentence depends on a term like
   "control-plane", "sidecar boundary", "lane", "COMMAND/TASK", "taint",
   "TDG", "runtime root", or similar internal shorthand, rewrite it unless
   that term is part of the actual user-facing product surface.
   - **Address the reader as "user" or "you", not "operator".** In
     end-user-facing text (CHANGELOG, README, quickstart, 2FA guide,
     USE-CASES), "operator" reads as jargon and makes the reader wonder
     whether you mean them or a separate software role. "Operator" is
     still appropriate in deployment/admin docs (`docs/DEPLOY.md`,
     `runner/RUNBOOK.md`, runbooks) and in threat-model/design docs
     where it names a distinct policy-author role separate from the
     end user.

4. **Bold the headline, then explain.** Start each Added/Security bullet with
   a short bold phrase, then follow with a plain sentence.
   - Example: `**Browser writes require user confirmation** and are scoped to
     the approved page context.`

5. **Separate end-user changes from infrastructure.** Supply-chain hardening,
   CI gates, and release pipeline changes matter, but most end-users will
   skip past them. Use sub-bullets under a parent item so readers can scan
   past if they don't care.

6. **Stay truth-scoped.** Don't overclaim. If a feature requires configuration
   or only works in certain modes, say so. Prefer "when X is configured" over
   implying it works universally.

7. **Drop implementation details unless they matter to the end-user.**
   Internal class names, registry names, schema types, layer numbers, and
   enforcement mechanics belong in commit messages or architecture docs, not
   the changelog. Rewrite phrases like "committed intent", "Tool Dependency
   Graph", "missing-path side effects", "metadata-only audit event", and
   "structured deny metadata" into plain descriptions of what the user sees.
   Mention the mechanism only after the end-user-facing effect is already
   clear, and only when it helps explain limits or setup.

8. **Expand acronyms on first use across the CHANGELOG.** Treat the whole
   file as one continuous document from a reader's perspective — they may
   read it top-to-bottom when catching up on a project. The first time an
   acronym appears in the file (counting from the newest release down),
   write the expansion in parentheses: `KMS (Key Management Service)`,
   `MCP (Model Context Protocol)`, `ACP (Agent Client Protocol)`. Subsequent
   appearances in older sections can use the bare acronym. Do not rewrite
   already-tagged sections to add expansions; instead, add the expansion in
   the newest section where the acronym appears, and it back-fills the
   reader's understanding as they read older entries. Industry-standard
   expansions only — do not invent an expansion that reads plausibly but
   is not the commonly-used form.

9. **Link public issue and PR provenance in a standard suffix.** When a
   changelog entry maps to a public GitHub issue or pull request, end the
   bullet with a parenthesized Markdown link suffix after the user-facing
   sentence. Use full GitHub URLs so the links work in GitHub Releases,
   PyPI-rendered project pages, and plain Markdown readers.
   - Issue only: `([#37](https://github.com/shisa-ai/shisad/issues/37))`
   - Pull request only:
     `([PR #32](https://github.com/shisa-ai/shisad/pull/32))`
   - Issue fixed by a PR:
     `([#26](https://github.com/shisa-ai/shisad/issues/26), [PR #32](https://github.com/shisa-ai/shisad/pull/32))`
   - If one bullet covers several public issues, prefer splitting the bullet.
     If the bundle is intentionally one user-facing change, list the parent
     issue first, then the most relevant child issues. Do not turn a
     changelog bullet into an exhaustive issue index.
   - Do not link private issues, private planning IDs, internal review IDs, or
     public issues that are only process context rather than source
     provenance for the shipped change.
   - If no public issue or PR exists, omit the suffix.

10. **Use a quick jargon smell test before you ship it.** Read each bullet and
   ask:
   - Would an end-user understand this without knowing our internal system names?
   - Does the first sentence say what changed for them, not what we built?
   - Could they explain it back after one read?
   If not, rewrite it.

11. **Prefer everyday product language over internal threat language.** Write
    what the end-user can notice or act on. For example:
    - Better: "The daemon now warns when suspicious denied actions repeat."
    - Worse: "The daemon records structured deny metadata for taint bypass attempts and unattributed egress probes."

## Trusted Publishing Setup

The `publish.yml` workflow uses PyPI trusted publishing (OIDC). One-time
setup required on PyPI:

1. Go to https://pypi.org/manage/project/shisad/settings/publishing/
2. Add a new "GitHub Actions" trusted publisher:
   - Owner: `shisa-ai`
   - Repository: `shisad`
   - Workflow name: `publish.yml`
   - Environment name: `pypi-publish`
3. Create a GitHub Environment named `pypi-publish` in the repo settings
   (Settings > Environments) with a required-reviewers gate so the publish
   step requires confirmation.

After setup, the workflow can publish without any stored API tokens.

## Recovery from Workflow Failure

If the publish workflow fails before the package has been uploaded to
PyPI — for example, the `Run release validation` step catches a lint,
format, or test issue that `scripts/ci_preflight.sh` missed, or the build
step itself fails — the tag has been pushed but nothing has shipped. The
GitHub Release has not been created, no SBOM or attestation exists, and
PyPI does not have a package at that version. Recover by moving the tag
to a fix commit:

1. Fix the issue locally and run the relevant validation to confirm
   (for example `uv run ruff format --check .`, `uv run ruff check .`,
   and the targeted test lane that failed).
2. Commit as `fix: <what you changed> for vX.Y.Z release` so the release
   intent is clear in history.
3. Delete the remote tag: `git push origin :refs/tags/vX.Y.Z`.
4. Delete the local tag: `git tag -d vX.Y.Z`.
5. Re-tag at the fix commit: `git tag -a vX.Y.Z -m "vX.Y.Z" <sha>`.
6. Push the fix commit and the new tag:
   `git push origin main`, then `git push origin vX.Y.Z`.
7. Re-dispatch the publish workflow:
   `gh -R shisa-ai/shisad workflow run "Publish to PyPI" -f tag=vX.Y.Z`.

Tag moves are only safe before the package has been uploaded to PyPI. PyPI
filenames are immutable — once `shisad-X.Y.Z-py3-none-any.whl` has been
accepted, you cannot re-upload different contents at the same version. If
the package has already shipped to PyPI, cut `X.Y.(Z+1)` instead of moving
the tag.

Record the failure and the recovery in the active milestone/implementation
worklog so the next release's preflight can be tightened if the gap is
reproducible (for example, adding the missing check to
`scripts/ci_preflight.sh`).

## Emergency Manual Publish

If the workflow is unavailable, fall back to manual publishing:

```bash
uv publish dist/shisad-X.Y.Z-py3-none-any.whl dist/shisad-X.Y.Z.tar.gz
# or:
uvx --from twine twine upload dist/shisad-X.Y.Z-py3-none-any.whl dist/shisad-X.Y.Z.tar.gz
```

This path does not generate attestations or SBOM. Use only in emergencies
and document why the workflow was bypassed.

## Notes

- Do not publish from a dirty tree.
- Do not reuse old `dist/` artifacts; rebuild for every release.
- Immediate post-publish install checks may need `uvx --refresh` because
  resolver caches can lag a minute or two behind PyPI.
- If a historical tag is missing from `CHANGELOG.md`, backfill that entry
  before publishing the next version.
