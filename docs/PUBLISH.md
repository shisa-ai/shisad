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
- [ ] Update README/docs if install steps, CLI behavior, or security model
      changed
- [ ] Run release validation:
      `uv run ruff format --check .`
- [ ] Run release validation:
      `uv run ruff check .`
- [ ] Run release validation:
      `uv run pytest tests/ -q`
- [ ] Run behavioral gate:
      `uv run pytest tests/behavioral/ -q`
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
- [ ] Publish to PyPI:
      `uv publish dist/shisad-X.Y.Z-py3-none-any.whl dist/shisad-X.Y.Z.tar.gz`
- [ ] If `uv publish` is not configured, use the fallback:
      `uvx --from twine twine upload dist/shisad-X.Y.Z-py3-none-any.whl dist/shisad-X.Y.Z.tar.gz`
- [ ] Create a GitHub Release from the tag:
      `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file -` (pipe the
      matching `CHANGELOG.md` section, or use `--notes "..."` inline)
- [ ] Verify the published package:
      `uvx --refresh --from "shisad==X.Y.Z" shisad --help`
- [ ] Verify the GitHub Release, tag, and PyPI project page all show the new version
- [ ] Confirm the tree is clean: `git status -sb`

## Notes

- Do not publish from a dirty tree.
- Do not reuse old `dist/` artifacts; rebuild for every release.
- `uv publish` defaults to `dist/*`; either clear old artifacts first or pass
  the exact wheel + sdist paths.
- Immediate post-publish install checks may need `uvx --refresh` because
  resolver caches can lag a minute or two behind PyPI.
- If a historical tag is missing from `CHANGELOG.md`, backfill that entry
  before publishing the next version.
