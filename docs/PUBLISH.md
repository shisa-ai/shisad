# Publishing Checklist

Use this as the release checklist for cutting a new `shisad` version.

Scope:

- Use this checklist whenever preparing a new Git tag or publishing to PyPI.
- `CHANGELOG.md` is release-oriented, not an in-progress ledger. Add a new
  topmost version section when cutting a release; do not keep an `Unreleased`
  section.

## Versioning

Use semver-style bumps:

- Patch (`0.5.1`): bug fixes, packaging/docs-only releases, low-risk UX
  improvements.
- Minor (`0.6.0`): new user-facing capabilities, commands, or significant
  security/runtime features.
- Major (`1.0.0`): intentionally breaking changes to CLI behavior, config
  format, or security model that need explicit upgrade guidance.

## Version Locations

Version must be updated in both places:

- `pyproject.toml` — `version = "X.Y.Z"`
- `src/shisad/__init__.py` — `__version__ = "X.Y.Z"`

## Release Punch List

- [ ] Start from a clean tree: `git status -sb`
- [ ] Sync with the remote release base:
      `git fetch --tags origin` and `git pull --ff-only`
- [ ] Pick the next version number and decide patch/minor/major
- [ ] Update version in `pyproject.toml`
- [ ] Update version in `src/shisad/__init__.py`
- [ ] Sync the lockfile: `uv lock`
- [ ] Update `CHANGELOG.md`:
      add a new topmost `## [X.Y.Z] - YYYY-MM-DD` section and update the
      version comparison links at the bottom
- [ ] Review `README.md` and top-level operator docs for release parity:
      `docs/ROADMAP.md`, `docs/ENV-VARS.md`, `docs/TOOL-STATUS.md`,
      `docs/USE-CASES.md`
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
- [ ] Run release validation:
      `uv run pytest tests/ -q`
- [ ] Run adversarial release gate:
      `uv run pytest tests/adversarial -q`
- [ ] Run behavioral gate:
      `uv run pytest tests/behavioral/ -q`
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
- [ ] Remove stale build artifacts:
      `rm -rf dist/`
- [ ] Build fresh artifacts:
      `uv build`
- [ ] Verify package metadata:
      `uvx --from twine twine check dist/*`
- [ ] Smoke-test the built wheel:
      `uv run --isolated --with dist/shisad-X.Y.Z-py3-none-any.whl shisad --help`
- [ ] Stage only release files explicitly and review them:
      `git add ...`, `git diff --staged --name-only`, `git diff --staged`
- [ ] Commit release metadata:
      `git commit -m "chore: prepare vX.Y.Z release"`
- [ ] Create an annotated tag:
      `git tag -a vX.Y.Z -m "vX.Y.Z"`
- [ ] Push the release commit and tag:
      `git push origin main`, `git push origin vX.Y.Z`
- [ ] Publish via trusted publishing workflow (primary path):
      Go to Actions > "Publish to PyPI" > Run workflow, enter `vX.Y.Z`.
      The workflow builds, runs tests, generates SBOM, creates attestations,
      and publishes via OIDC. Requires approval in the `pypi-publish`
      environment.
- [ ] Create a GitHub Release from the tag:
      `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file -` (pipe the
      matching `CHANGELOG.md` section, or use `--notes "..."` inline)
- [ ] Attach SBOM to the GitHub Release:
      download `sbom-shisad-X.Y.Z` artifact from the workflow run, then
      `gh release upload vX.Y.Z sbom-shisad-X.Y.Z.spdx.json`
- [ ] Verify the published package:
      `uvx --refresh --from "shisad==X.Y.Z" shisad --help`
- [ ] Verify the GitHub Release, tag, and PyPI project page all show the new
      version
- [ ] Verify attestation is visible on the PyPI project page
- [ ] Confirm the tree is clean: `git status -sb`

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
   (Settings > Environments) with required reviewers enabled.

After setup, the workflow can publish without any stored API tokens.

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
