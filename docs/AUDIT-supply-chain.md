# shisad Supply Chain Audit

*Created: 2026-03-31*  
*Status: Draft*  
*Snapshot basis: repository state on `main` at audit time (clean tree)*

## Scope and Intent

This document maps the current dependency chain and audits where version locking is strong vs weak.

Goals:

1. Provide a full dependency map (direct + upstream/transitive).
2. Identify non-locked or weakly-locked points in the chain.
3. Propose concrete hardening steps that reduce attack surface without disabling core functionality.

## Pre-analysis Notes

- Behavioral contract impact: none. This is documentation-only analysis and should not alter runtime behavior.
- Threat hotspots for supply chain in this repo today:
  - runtime `npx` adapter resolution,
  - mutable CI action tags,
  - unpinned build backend dependency,
  - installer/bootstrap paths that depend on mutable upstream endpoints.
- Accepted risk decision: Python interpreter version remains `>=3.12` and is not treated as a primary attack vector for this audit lane.

## Evidence and Commands (Snapshot Reproducibility)

The audit findings below are based on these commands run against the working tree:

```bash
git status -sb
uv lock --check
uv tree --all-groups
uv tree --no-dev --no-group channels-runtime --no-group coverage --no-group security-runtime
uv tree --only-group dev
uv tree --only-group channels-runtime
uv tree --only-group coverage
uv tree --only-group security-runtime
uv export --all-groups --frozen --format requirements.txt --no-hashes --no-header --no-annotate
uv export --all-groups --frozen --format requirements.txt --no-hashes --no-header
rg -o "source = \\{[^\\}]+\\}" uv.lock | sort | uniq -c
rg -c "^\\[\\[package\\]\\]" uv.lock
rg -n "hatchling|build-system" pyproject.toml uv.lock
rg -n "actions/checkout|setup-uv|upload-artifact|@v[0-9]+|uv sync" .github/workflows/ci.yml
rg -n "npx|@zed-industries|opencode-ai" src/shisad/coding/registry.py
sed -n '1,140p' docs/DEPLOY.md
```

## Dependency Map

### A. Python dependency chain summary

- `uv.lock` entries: `76` packages total.
- Third-party packages from registry: `75` (plus editable root package `shisad`).
- Registry source in lockfile: `75` entries from `https://pypi.org/simple`.
- Non-registry sources in lockfile: none (except local editable `shisad` root).

### B. Direct dependency declarations vs lock resolution

#### Runtime direct dependencies (`[project.dependencies]`)

| Package | Declared in `pyproject.toml` | Locked in `uv.lock` | Lock quality |
| --- | --- | --- | --- |
| `agent-client-protocol` | `==0.8.1` | `0.8.1` | Exact |
| `click` | `>=8.1,<9` | `8.3.1` | Range in spec, exact in lock |
| `cryptography` | `>=44.0,<46` | `45.0.7` | Range in spec, exact in lock |
| `loguru` | `>=0.7,<1` | `0.7.3` | Range in spec, exact in lock |
| `pydantic` | `>=2.10,<3` | `2.12.5` | Range in spec, exact in lock |
| `pydantic-settings` | `>=2.7,<3` | `2.12.0` | Range in spec, exact in lock |
| `pyyaml` | `>=6.0,<7` | `6.0.3` | Range in spec, exact in lock |

#### Dependency groups (`[dependency-groups]`)

| Group | Direct packages in group | Lock status |
| --- | --- | --- |
| `dev` | `pytest`, `pytest-asyncio`, `ruff`, `mypy`, `types-pyyaml`, `textual` | All exact in lock; all declared as ranges |
| `channels-runtime` | `matrix-nio[e2e]`, `discord.py`, `python-telegram-bot`, `slack-bolt`, `slack-sdk` | All exact in lock; all declared as ranges |
| `coverage` | `pytest-cov` | Exact in lock; declared as range |
| `security-runtime` | `yara-python` | Exact in lock; declared as range |

### C. Full upstream package inventory (all groups)

The full locked package set (third-party only) at snapshot time:

```text
agent-client-protocol==0.8.1
aiofiles==24.1.0
aiohappyeyeballs==2.6.1
aiohttp==3.13.3
aiohttp-socks==0.11.0
aiosignal==1.4.0
annotated-types==0.7.0
anyio==4.12.1
atomicwrites==1.4.1
attrs==25.4.0
audioop-lts==0.2.2 ; python_full_version >= '3.13'
cachetools==5.5.2
certifi==2026.1.4
cffi==2.0.0
click==8.3.1
colorama==0.4.6 ; sys_platform == 'win32'
coverage==7.13.4
cryptography==45.0.7
discord-py==2.6.4
frozenlist==1.8.0
h11==0.16.0
h2==4.3.0
hpack==4.1.0
httpcore==1.0.9
httpx==0.28.1
hyperframe==6.1.0
idna==3.11
iniconfig==2.3.0
jsonschema==4.26.0
jsonschema-specifications==2025.9.1
librt==0.7.8 ; platform_python_implementation != 'PyPy'
linkify-it-py==2.0.3
loguru==0.7.3
markdown-it-py==4.0.0
matrix-nio==0.25.2
mdit-py-plugins==0.5.0
mdurl==0.1.2
multidict==6.7.1
mypy==1.19.1
mypy-extensions==1.1.0
packaging==26.0
pathspec==1.0.4
peewee==3.19.0
platformdirs==4.9.2
pluggy==1.6.0
propcache==0.4.1
pycparser==3.0 ; implementation_name != 'PyPy'
pycryptodome==3.23.0
pydantic==2.12.5
pydantic-core==2.41.5
pydantic-settings==2.12.0
pygments==2.19.2
pytest==8.4.2
pytest-asyncio==0.26.0
pytest-cov==6.3.0
python-dotenv==1.2.1
python-olm==3.2.16
python-socks==2.8.0
python-telegram-bot==21.11.1
pyyaml==6.0.3
referencing==0.37.0
rich==14.3.2
rpds-py==0.30.0
ruff==0.15.0
slack-bolt==1.27.0
slack-sdk==3.40.0
textual==0.89.1
types-pyyaml==6.0.12.20250915
typing-extensions==4.15.0
typing-inspection==0.4.2
uc-micro-py==1.0.3
unpaddedbase64==2.1.0
win32-setctime==1.2.0 ; sys_platform == 'win32'
yara-python==4.5.4
yarl==1.22.0
```

### D. Upstream edge map (who pulls what)

Immediate upstream edges from the lock export (`uv export --all-groups --frozen --format requirements.txt --no-hashes --no-header`):

```text
agent-client-protocol==0.8.1
    # via shisad
aiofiles==24.1.0
    # via matrix-nio
aiohappyeyeballs==2.6.1
    # via aiohttp
aiohttp==3.13.3
    # via
    #   aiohttp-socks
    #   discord-py
    #   matrix-nio
aiohttp-socks==0.11.0
    # via matrix-nio
aiosignal==1.4.0
    # via aiohttp
annotated-types==0.7.0
    # via pydantic
anyio==4.12.1
    # via httpx
atomicwrites==1.4.1
    # via matrix-nio
attrs==25.4.0
    # via
    #   aiohttp
    #   jsonschema
    #   referencing
audioop-lts==0.2.2 ; python_full_version >= '3.13'
    # via discord-py
cachetools==5.5.2
    # via matrix-nio
certifi==2026.1.4
    # via
    #   httpcore
    #   httpx
cffi==2.0.0
    # via
    #   cryptography
    #   python-olm
click==8.3.1
    # via shisad
colorama==0.4.6 ; sys_platform == 'win32'
    # via
    #   click
    #   loguru
    #   pytest
coverage==7.13.4
    # via pytest-cov
cryptography==45.0.7
    # via shisad
frozenlist==1.8.0
    # via
    #   aiohttp
    #   aiosignal
h11==0.16.0
    # via
    #   httpcore
    #   matrix-nio
h2==4.3.0
    # via matrix-nio
hpack==4.1.0
    # via h2
httpcore==1.0.9
    # via httpx
httpx==0.28.1
    # via python-telegram-bot
hyperframe==6.1.0
    # via h2
idna==3.11
    # via
    #   anyio
    #   httpx
    #   yarl
iniconfig==2.3.0
    # via pytest
jsonschema==4.26.0
    # via matrix-nio
jsonschema-specifications==2025.9.1
    # via jsonschema
librt==0.7.8 ; platform_python_implementation != 'PyPy'
    # via mypy
linkify-it-py==2.0.3
    # via markdown-it-py
loguru==0.7.3
    # via shisad
markdown-it-py==4.0.0
    # via
    #   mdit-py-plugins
    #   rich
    #   textual
mdit-py-plugins==0.5.0
    # via markdown-it-py
mdurl==0.1.2
    # via markdown-it-py
multidict==6.7.1
    # via
    #   aiohttp
    #   yarl
mypy-extensions==1.1.0
    # via mypy
packaging==26.0
    # via pytest
pathspec==1.0.4
    # via mypy
peewee==3.19.0
    # via matrix-nio
platformdirs==4.9.2
    # via textual
pluggy==1.6.0
    # via
    #   pytest
    #   pytest-cov
propcache==0.4.1
    # via
    #   aiohttp
    #   yarl
pycparser==3.0 ; implementation_name != 'PyPy'
    # via cffi
pycryptodome==3.23.0
    # via matrix-nio
pydantic-core==2.41.5
    # via pydantic
python-dotenv==1.2.1
    # via pydantic-settings
python-olm==3.2.16
    # via matrix-nio
python-socks==2.8.0
    # via aiohttp-socks
referencing==0.37.0
    # via
    #   jsonschema
    #   jsonschema-specifications
rich==14.3.2
    # via textual
rpds-py==0.30.0
    # via
    #   jsonschema
    #   referencing
slack-sdk==3.40.0
    # via slack-bolt
typing-extensions==4.15.0
    # via
    #   aiosignal
    #   anyio
    #   mypy
    #   pydantic
    #   pydantic-core
    #   referencing
    #   textual
    #   typing-inspection
typing-inspection==0.4.2
    # via
    #   pydantic
    #   pydantic-settings
uc-micro-py==1.0.3
    # via linkify-it-py
unpaddedbase64==2.1.0
    # via matrix-nio
win32-setctime==1.2.0 ; sys_platform == 'win32'
    # via loguru
yarl==1.22.0
    # via aiohttp
```

Note: packages with no `# via` comments in this export are direct dependencies of `shisad` in one of the groups.

## Lock Status Audit (Where We Are and Are Not Locked)

### Strongly locked today

1. **Python resolved dependency graph (`uv.lock`)**
   - Exact package versions are locked.
   - Artifact hashes are recorded for sdists/wheels.
   - Registry source is explicit (`https://pypi.org/simple`).

2. **Core project lockfile hygiene**
   - `uv lock --check` is currently clean.
   - The lockfile is committed and used in normal workflows.

### Partially locked / weak points

1. **`pyproject.toml` direct dependency specs are mostly ranges**
   - Only 1 direct runtime dep is exact-pinned (`agent-client-protocol`).
   - Remaining direct deps and group deps are range-pinned and rely on `uv.lock` for exactness.

2. **Build backend dependency is not version pinned**
   - `build-system.requires = ["hatchling"]` is unbounded in `pyproject.toml`.
   - This is outside the regular app dependency lock graph and should be treated as a supply-chain surface.

3. **Runtime npm adapter path is not fully immutable**
   - `src/shisad/coding/registry.py` uses `npx` at runtime.
   - `claude` and `codex` adapters include explicit package versions.
   - `opencode` adapter currently does not include a version (`opencode-ai` unpinned).
   - None of these runtime npm resolves are hash-pinned in-repo.

4. **CI action references are mutable tags**
   - `.github/workflows/ci.yml` uses tags such as:
     - `actions/checkout@v4`
     - `astral-sh/setup-uv@v4`
     - `actions/upload-artifact@v4`
   - Tags are not immutable trust anchors compared to full commit SHAs.

5. **CI install commands do not assert frozen lock usage**
   - CI uses `uv sync ...` without `--frozen`.
   - Using `--frozen` hardens against accidental lock drift in CI execution.

6. **Bootstrap/install path includes mutable upstream installers**
   - `docs/DEPLOY.md` bootstrap includes:
     - `apt-get install ...` with no package version pinning.
     - `curl -LsSf https://astral.sh/uv/install.sh | sh`.
   - This is common operationally but is not reproducible/immutable supply chain by default.

### Explicitly accepted risk

1. **Python interpreter version pinning**
   - Project metadata allows `requires-python = ">=3.12"`.
   - `.python-version` pins major/minor (`3.12`) but not patch.
   - This audit treats interpreter patch-level drift as an accepted, lower-priority risk per project stance.

## Prioritized Hardening Plan

### Priority 0 (fast, high-value)

1. Pin `opencode` adapter version in `src/shisad/coding/registry.py`.
2. Add CI `--frozen` to all `uv sync` steps.
3. Pin GitHub Actions to immutable commit SHAs (keep a small process for scheduled SHA refresh).
4. Pin `build-system.requires` to an explicit `hatchling` version range or exact version.

### Priority 1 (next release lane)

1. Add a production mode that disallows live runtime `npx` registry fetches and requires preinstalled adapters.
2. Define and document a standard "approved internal package mirror/proxy" pattern for Python and npm.
3. Add a periodic dependency-audit job that emits:
   - full package inventory,
   - lock diff summary,
   - newly introduced packages since last release.

### Priority 2 (roadmap-aligned, medium term)

1. Move release publishing to trusted publishing + provenance attestations.
2. Add release SBOM generation and signing.
3. When container images are introduced, require digest pinning and signature verification in release policy.

## Suggested Policy Language (for future docs alignment)

- Keep capability posture functional: hardening must not disable normal user workflows.
- Treat `uv.lock` as mandatory release input and lockfile diffs as security-sensitive changes.
- Prefer immutable references at every layer:
  - package versions + hashes,
  - action SHAs,
  - signed artifacts,
  - pinned image digests.
- Keep explicit accepted risks documented (Python version range currently accepted).

## Current Bottom Line

- Python package supply chain is reasonably strong at the lockfile layer.
- The largest practical gaps are outside that layer:
  - runtime npm fetch path,
  - mutable CI action pins,
  - unpinned build backend,
  - mutable bootstrap installers.
- Addressing those four items gives the highest near-term reduction in supply-chain risk without reducing product functionality.
