# shisad Supply Chain Audit

*Created: 2026-03-31*  
*Updated: 2026-08-06 (v0.8.2 O0 dependency intake)*
*Status: In Progress*  
*Snapshot basis: code/dependency and workflow state in the v0.8.1 release published on 2026-07-28; `shisad@a16c15a` for the 2026-05-07 Dependabot 21 Ledger bridge remediation; and the 2026-06-03 Codex ACP adapter refresh to `@zed-industries/codex-acp@0.15.0`. Historical v0.7.0-v0.8.0 release evidence is retained where explicitly labeled. This snapshot includes no registry image.*

## Scope and Intent

This document maps the current dependency chain and audits where version locking is strong vs weak.

Goals:

1. Provide a full dependency map (direct + upstream/transitive).
2. Identify non-locked or weakly-locked points in the chain.
3. Propose concrete hardening steps that reduce attack surface without disabling core functionality.

## Repo Profile

| Item | Value |
| --- | --- |
| Primary ecosystem | Python |
| Secondary ecosystem | Optional Node subproject: `contrib/ledger-bridge/`; local Linux/amd64 OCI candidate |
| Package manager | uv; npm for the optional Ledger bridge |
| Lockfile | `uv.lock`; `contrib/ledger-bridge/package-lock.json` |
| CI install path | `uv sync --exclude-newer P7D --frozen --dev`; focused groups plus an opt-in clean-wheel/image job |
| Release path | PyPI: GitHub Actions `publish.yml` via OIDC; container: local candidate only, no registry path |
| Current risk summary | Python runtime resolutions remain hash-locked and no release-audit ignore is configured, but the all-groups audit now fails on a newly published high `cryptography 48.0.1` advisory whose first patched version (`50.0.0`) is not released. Optional-channel `aiohttp` and all current optional Ledger bridge advisories are resolved in the working candidate. The local image pins its Linux/amd64 Python base digest and excludes build/test tooling from the final stage. Debian package resolution and builder-tool transitive resolution remain build-time mutable, and no container registry signing/attestation path exists yet. |

## Pre-analysis Notes

- Behavioral contract impact: none. This is documentation-only analysis and should not alter runtime behavior.
- Threat hotspots for supply chain in this repo today:
  - runtime `npx` adapter resolution,
  - mutable CI action tags,
  - workflow-level coverage gaps in CI security checks and release-path controls,
  - installer/bootstrap paths that depend on mutable upstream endpoints.
- Accepted risk decision: Python interpreter version remains `>=3.12` and is not treated as a primary attack vector for this audit lane.

## Follow-up Worklog

### 2026-08-06 — v0.8.2 O0 dependency intake

- Optional Python channel resolution:
  - `uv --no-config lock --upgrade-package aiohttp` changed only locked
    `aiohttp 3.14.1 -> 3.14.3`; the direct dependency declarations and base
    install remain unchanged.
  - `uv --no-config lock --check` passed. A frozen `assistant` sync imported
    `aiohttp 3.14.3`, `discord.py 2.6.4`, and `matrix-nio 0.25.2`, preserving
    both supported optional-channel consumers.
- Python audit disposition:
  - The exact hash-enforced release command,
    `uvx pip-audit --require-hashes --disable-pip -r <(uv --no-config export
    --all-groups --frozen --format requirements.txt --no-emit-project)`,
    reports `cryptography 48.0.1` advisories after the `aiohttp` fix.
  - Dependabot alert `87` confirms the high PKCS#7 oracle advisory affects
    `>=44,<50`; upstream identifies unreleased `50.0.0` as the first patched
    version. Shisad has no direct PKCS#7 decrypt call, but that bounds current
    exposure rather than proving safety for every dependency path.
  - The human lead approved retaining `cryptography>=48.0.1,<49`, adding no
    audit-ignore, and treating this as a v0.8.2 release blocker until a
    compatible fixed release is locked and validated or a ReleaseClose risk
    exception is explicitly approved after final review. Two lower-severity
    audit records whose GitHub affected ranges end at `48.0.0` remain visible
    for database reconciliation and re-audit.
- Optional Ledger bridge resolution:
  - The red `npm audit --json` reported `9` vulnerability groups (`1` low,
    `3` moderate, `5` high) through the opt-in Ledger tree.
  - Existing transitive override posture now pins `axios 1.18.0`, `esbuild
    0.28.1`, `form-data 4.0.6`, `qs 6.15.2`, and `ws 8.21.0`; the existing
    `uuid 11.1.1` override and all direct Ledger package pins are unchanged.
  - `npm ci` installed `105` packages with zero vulnerabilities. `npm test`
    passed all `6` bridge protocol tests,
    `npx tsc --noEmit` passed, and both `npm audit --json` and
    `npm audit --omit=dev --json` returned zero vulnerabilities.
  - This changes no bridge route, hardware protocol, default-off posture, or
    base Python installation claim.

### 2026-07-30 — GH #100 managed-environment source checkout

- Reproduction:
  - `uv --no-config sync --group dev --extra chat --dry-run --python 3.12
    --exclude-newer 2026-05-20T00:00:00Z --no-build` reproduces the reported
    unsatisfiable `cryptography>=48.0.1,<49` split.
  - A Python-3.12-only `uv pip compile` under the same cutoff also fails on
    `cryptography`, proving that uv's newer-Python hint is not the root cause.
  - `cryptography 48.0.1` was uploaded on 2026-06-09, after the environment's
    fixed 2026-05-20 cutoff. Versions before 48.0.1 are affected by
    [GHSA-537c-gmf6-5ccf](https://github.com/pyca/cryptography/security/advisories/GHSA-537c-gmf6-5ccf),
    so lowering the direct minimum would restore a known vulnerable wheel.
- Accepted contract:
  - documented source-checkout setup commands use the repository's committed,
    hash-locked resolution with `uv --no-config sync --frozen`;
  - stale discovered user/system uv config cannot silently replace that
    repository-owned setup posture; explicit `UV_*` variables and CLI
    overrides remain caller-owned;
  - supported Python metadata and the patched cryptography floor remain
    unchanged;
  - users intentionally evaluating a different package-age universe must move
    their cutoff past every required security floor rather than weakening the
    project.
- Affected files:
  - setup documentation: `README.md`, `docs/DEPLOY.md`, `runner/README.md`,
    `runner/RUNBOOK.md`, and `runner/SKILL.md`;
  - contract/evidence: this audit and
    `tests/unit/test_runner_agent_harness.py`;
  - production files, `pyproject.toml`, and `uv.lock`: none.
- Pre-analysis:
  - product implication: managed development environments must remain usable
    without trading away the patched dependency baseline;
  - threat hotspots: discovered resolver config overriding the committed lock,
    stale package-age cutoffs, global no-build config in a source checkout,
    explicit caller overrides, and misleading Python-version narrowing;
  - runtime wiring: none; the shipped daemon is unchanged. The live path is
    the documented source-checkout command and uv's frozen lock consumption;
  - refactor selection: none. This is a docs/contract-test unit with no
    opportunistic production-file overlap;
  - validation: red-first documentation/command contract test, exact Python
    3.12 hostile-config dry run with lock immutability, Python 3.13 best-effort
    frozen dry run, Ruff for the changed test, and lockfile integrity check;
  - likely deferral: general compatibility with arbitrary organization-owned
    uv policies remains external to this repository.
- Outcome:
  - all documented source-checkout sync commands now consume the frozen lock
    without discovered uv config; the quoted invalid troubleshooting command
    remains only as the failure being diagnosed;
  - `pyproject.toml` and `uv.lock` are unchanged, so the supported-Python
    contract and patched dependency floor remain intact;
  - the red-first `GH100-R1` node initially failed on the ambient-config-
    sensitive commands, then passed as `1 passed`; the owning
    `tests/unit/test_runner_agent_harness.py` file passed all `23` tests;
  - Ruff passed for the changed test, `uv --no-config lock --check` resolved
    all `134` packages, and frozen dry-runs passed on installed Python 3.12 and
    best-effort Python 3.13;
  - independent read-only review reported no remaining findings against the
    accepted contract.

### 2026-07-28 — v0.8.1 ReleaseClose dependency remediation

- Scope: audit the frozen `uv export --all-groups` dependency set and the
  publish-workflow exception list for the pre-tag candidate.
- Initial audit:
  - `pip-audit` reported nine fixed advisories across locked `click 8.3.1`,
    `mcp 1.27.0`, `onnx 1.21.0`, `setuptools 81.0.0`, and `torch 2.12.1`.
  - The direct lower bounds now exclude the vulnerable lines:
    `click>=8.3.3`, `mcp>=1.28.1`, `onnx>=1.22`, and `torch>=2.13`.
  - The lock now resolves `click 8.4.2`, `mcp 1.28.1`, `onnx 1.22.0`,
    `setuptools 83.0.0`, and `torch 2.13.0`.
- Supported resolution posture:
  - `[tool.uv].environments` limits the universal development lock to Darwin,
    Windows, and Linux other than `s390x`, matching the release's tested
    platform scope. The unsupported `s390x` CUDA branch published no artifact
    hash usable by the release audit and is not part of a shisad support claim.
- Exception cleanup:
  - The post-update hash-enforced `pip-audit` returned `No known
    vulnerabilities found`.
  - All historical `--ignore-vuln` flags were removed from `publish.yml`; the
    publish audit is again fail-closed with no advisory exceptions.

### 2026-06-25 — v0.8.0b0 release-audit dependency refresh

- Scope: remediate Python dependency-audit blockers found while publishing the
  v0.8.0b0 beta checkpoint across the frozen `uv export --all-groups`
  dependency set.
- Audit result:
  - The publish workflow initially reported advisories in locked `aiohttp
    3.13.5`, `cryptography 46.0.7`, `pydantic-settings 2.12.0`, `pyjwt
    2.12.1`, `python-multipart 0.0.27`, `starlette 1.0.0`, and `torch
    2.11.0`.
  - `uv --no-config lock --upgrade-package aiohttp --upgrade-package
    cryptography --upgrade-package pydantic-settings --upgrade-package pyjwt
    --upgrade-package python-multipart --upgrade-package starlette
    --upgrade-package torch` resolved patched versions:
    `aiohttp 3.14.1`, `cryptography 48.0.1`, `pydantic-settings 2.14.2`,
    `pyjwt 2.13.0`, `python-multipart 0.0.32`, `starlette 1.3.1`, and
    `torch 2.12.1`.
  - `pyproject.toml` now declares `cryptography>=48.0.1,<49`; the previous
    `<47` cap blocked the patched release line.
  - The publish-workflow `pip-audit` command then returned `No known
    vulnerabilities found`.
- Risk disposition:
  - No new ignore was added for this release-audit batch.
  - The existing no-fix exception set remains limited to the advisory IDs
    already listed in the publish workflow.

### 2026-05-21 — v0.7.4 pip-audit no-fix exception review

- Scope: release-close Python dependency audit for the v0.7.4 candidate across
  the frozen `uv export --all-groups` dependency set.
- Audit result:
  - `uvx pip-audit --require-hashes --disable-pip -r <(uv --no-config export
    --all-groups --frozen --format requirements.txt --no-emit-project
    --directory /home/ubuntu/shisad)` initially reported 22 advisories across
    `idna`, `onnx`, `pyjwt`, `torch`, and `transformers`.
  - `idna` had a fixed version, so the lock was updated with
    `uv --no-config lock --directory /home/ubuntu/shisad --upgrade-package
    idna==3.15`.
  - The remaining advisory set has no fixed version in the PyPA advisory data
    consumed by `pip-audit`, or is disputed/no-fix upstream. The publish
    workflow ignores only the explicit advisory IDs listed below; any new or
    unlisted advisory remains a blocking `pip-audit` failure.
- Exception set:
  - `PYSEC-2025-183` / `CVE-2025-45768` (`pyjwt`): transitive through `mcp`
    in the dev/interop path. No local shisad code imports PyJWT; local JWT
    handling is secret redaction only. The advisory is supplier-disputed and
    has no fixed PyPA version.
  - `PYSEC-2025-148` / `CVE-2025-51480` (`onnx`): `security-build` model-pack
    build lane only, not daemon runtime. NVD identifies ONNX `1.17.0` and
    references upstream patch PRs, while the PyPA advisory currently exposes no
    fixed version range for the locked `1.21.0`.
  - `PYSEC-2025-189`, `PYSEC-2025-190`, `PYSEC-2025-191`,
    `PYSEC-2025-192`, `PYSEC-2025-193`, `PYSEC-2025-194`,
    `PYSEC-2025-195`, `PYSEC-2025-196`, `PYSEC-2025-197`,
    `PYSEC-2025-210`, and `PYSEC-2026-139` (`torch`): build-only
    `security-build` dependency for PromptGuard export/model-pack tooling.
    The live daemon runtime does not require this group.
  - `PYSEC-2025-211`, `PYSEC-2025-212`, `PYSEC-2025-213`,
    `PYSEC-2025-214`, `PYSEC-2025-215`, `PYSEC-2025-216`,
    `PYSEC-2025-217`, and `PYSEC-2025-218` (`transformers`): optional
    PromptGuard/textguard path. shisad's runtime contract loads local ONNX
    PromptGuard artifacts through `textguard[promptguard]` and signed-pack
    verification; it does not fetch or convert arbitrary checkpoints as part
    of ordinary daemon startup.
- Risk disposition:
  - Release audit remains fail-closed for all advisories outside the explicit
    exception set.
  - Recheck this exception set on every release close and remove individual
    ignores as soon as PyPA exposes fixed versions or the optional build/runtime
    dependency path can move to unaffected packages.

### 2026-05-07 — Dependabot 21 Ledger bridge uuid remediation

- Scope: remediate Dependabot alert `21` for the optional Ledger bridge runtime
  transitive `uuid` advisory.
- Investigation:
  - `gh api repos/shisa-ai/shisad/dependabot/alerts/21 --jq ...` returned
    open alert `21`, GHSA `GHSA-w5hq-g745-h8pq`, vulnerable range
    `>= 11.0.0, < 11.1.1`, and patched version `11.1.1`.
  - `npm view @ledgerhq/device-management-kit@latest version
    dependencies.uuid --json` returned latest `1.4.0` with
    `dependencies.uuid = 11.0.3`.
  - `npm view @ledgerhq/device-transport-kit-node-hid@latest version
    dependencies.uuid --json` returned latest `1.0.1` with
    `dependencies.uuid = 11.0.3`.
  - A direct Ledger package refresh alone therefore does not clear the alert
    today.
- Change:
  - Added a local npm override from `uuid 11.0.3` to patched `uuid 11.1.1`
    beside the existing `axios` override and regenerated the Ledger bridge
    lockfile with `npm install --package-lock-only --ignore-scripts`.
  - The lockfile now resolves `uuid 11.1.1` with integrity
    `sha512-vIYxrBCC/N/K+Js3qSN88go7kIfNPssr/hHCesKCQNAjmgvYS2oqr69kIufEG+O4+PfezOH4EbIeHCfFov8ZgQ==`.
  - `npm ls uuid --all` shows both `@ledgerhq/device-management-kit@1.2.0`
    and `@ledgerhq/device-transport-kit-node-hid@1.0.1` resolving
    `uuid@11.1.1`.
- Validation:
  - `npm ci --ignore-scripts` exited 0 from a fresh lockfile install and
    reported `found 0 vulnerabilities`.
  - `npm audit --json` exited 0 with `0` vulnerabilities.
  - `npm audit --omit=dev --json` exited 0 with `0` vulnerabilities.
  - `npm audit --omit=dev --audit-level=high` exited 0.
  - `npm test` passed all Ledger bridge tests: 6 passed / 0 failed.
  - `npx tsc --noEmit` passed.
- Disposition:
  - Close `SC-v0.7.0-ledger-uuid` locally. If Dependabot does not auto-close
    after this lockfile lands and GitHub rescans, the follow-up should be alert
    state investigation rather than a Ledger SDK downgrade.

### 2026-05-07 — v0.7.2 Ledger bridge uuid recheck

- Scope: refresh the carried `SC-v0.7.0-ledger-uuid` optional Ledger bridge
  npm advisory during v0.7.2 ReleaseClose remediation.
- Audit result:
  - `npm audit --omit=dev --audit-level=high` in `contrib/ledger-bridge/`
    exited 0. npm still printed the residual moderate `uuid` advisory family,
    but reported 0 high and 0 critical advisories.
  - `npm audit --omit=dev --json` in `contrib/ledger-bridge/` exited 1 with
    metadata `6 moderate / 0 high / 0 critical` advisories.
  - The remaining advisory is `uuid <14` / GHSA-w5hq-g745-h8pq through Ledger
    SDK packages. The available forced fix would install
    `@ledgerhq/device-management-kit@0.6.5` as a breaking downgrade, while
    `@ledgerhq/device-transport-kit-node-hid` reports no direct fix path.
- Disposition:
  - No new high/critical npm advisory blocks v0.7.2 release close.
  - The exception stays open because the current compatible Ledger package set
    still does not provide a clean fixed `uuid` path.
  - The target is now post-v0.7.2 / the next Ledger bridge dependency refresh,
    whichever comes first.

### 2026-05-06 — v0.7.2 python-multipart pip-audit remediation

- Scope: remediate the Python dependency-audit blocker found during v0.7.2
  release-close preflight.
- Audit result:
  - `uvx pip-audit --require-hashes --disable-pip -r <(uv export --all-groups
    --frozen --format requirements.txt --no-emit-project --directory
    /home/ubuntu/shisad)` initially reported `CVE-2026-42561` in transitive
    `python-multipart 0.0.26` via `mcp`.
  - `uv lock --directory /home/ubuntu/shisad --upgrade-package
    python-multipart` -> `Updated python-multipart v0.0.26 -> v0.0.27`.
  - `uv lock --check --directory /home/ubuntu/shisad` passed.
  - The same `pip-audit` command then returned `No known vulnerabilities
    found`.
  - The maintainer-side supply-chain parity helper returned
    `Supply-chain audit parity: OK`.
- Risk disposition:
  - The Python release-close audit blocker is closed for this candidate.
  - `python-multipart` remains a transitive interop/dev dependency through
    `mcp`, not a base-runtime default dependency.

### 2026-04-30 — v0.7.1 Ledger bridge uuid recheck

- Scope: recheck the carried `SC-v0.7.0-ledger-uuid` optional Ledger bridge
  npm advisory during v0.7.1 release close.
- Audit result:
  - `npm audit --omit=dev --audit-level=high` in
    `contrib/ledger-bridge/` -> exit 0.
  - `npm audit --omit=dev --json` in `contrib/ledger-bridge/` -> exit 1
    with 6 moderate, 0 high, and 0 critical advisories.
  - The remaining advisory is `uuid <14` / GHSA-w5hq-g745-h8pq through
    Ledger SDK packages. npm still reports no non-breaking compatible fix for
    `uuid`, `@ledgerhq/device-management-kit`,
    `@ledgerhq/device-signer-kit-ethereum`,
    `@ledgerhq/device-transport-kit-node-hid`, or
    `@ledgerhq/signer-utils`. The suggested `@ledgerhq/context-module@0.1.2`
    path is semver-major and incompatible with the accepted bridge tree.
- Risk disposition:
  - No new high/critical npm advisory blocks v0.7.1 release close.
  - The exception stays open because the current compatible Ledger package set
    still does not provide a clean fixed `uuid` path.
  - The optional bridge remains disabled by default, loopback-only, and bearer
    token capable; no default shisad runtime path imports this Node dependency
    tree.

### 2026-04-25 — v0.7.0 Ledger bridge axios override refresh

- Scope: fold the approved Ledger bridge axios CVE remediation into the
  `v0.7.0` release target after the full release-close validation bundle had
  already passed on `shisad@6227022`.
- Dependency remediation:
  - Added a root npm `overrides` entry in `contrib/ledger-bridge/package.json`
    requiring `axios@^1.15.2`.
  - Refreshed `contrib/ledger-bridge/package-lock.json`; the committed lockfile
    now resolves Ledger SDK axios paths to `axios@1.15.2` and
    `proxy-from-env@2.1.0`.
- Audit and test result:
  - `npm install --package-lock-only --ignore-scripts` in
    `contrib/ledger-bridge/` -> `up to date`; lockfile remains consistent.
  - `npm ls axios proxy-from-env --all` -> both `@ledgerhq/context-module` and
    `@ledgerhq/device-management-kit` resolve through `axios@1.15.2`, with
    `proxy-from-env@2.1.0`.
  - `npm test` -> `6 passed`.
  - `npm audit --omit=dev --audit-level=high` -> exit 0.
  - Residual npm audit output is the existing moderate `uuid <14` advisory
    surfaced through Ledger SDK packages (`@ledgerhq/device-management-kit`,
    `@ledgerhq/device-transport-kit-node-hid`, and dependents). npm reports no
    compatible non-breaking fix through the current Ledger package set.
- Risk disposition:
  - The prior Ledger axios advisory exception is closed for `v0.7.0`.
  - The remaining open exception is tracked as `SC-v0.7.0-ledger-uuid`.
  - The bridge remains optional, disabled by default, loopback-only, and bearer
    token capable; no core Python install path or default shisad runtime path
    imports this Node dependency tree.

### 2026-04-23 — v0.7.0 candidate release-close parity refresh

- Scope: refresh the dependency audit for the `v0.7.0` release-prepared
  candidate on `main` after the memory-foundation line and release-prep
  version bump.
- Python audit result:
  - `uv lock --check` passed on `/home/ubuntu/shisad`.
  - `uvx pip-audit --require-hashes --disable-pip -r <(uv export --all-groups
    --frozen --format requirements.txt --no-emit-project --directory
    /home/ubuntu/shisad)` initially found `CVE-2026-28684` in transitive
    `python-dotenv 1.2.1` via `pydantic-settings`; the candidate now pins
    `python-dotenv>=1.2.2,<2` and refreshes `uv.lock`.
  - The maintainer-side supply-chain parity helper returned
    `Supply-chain audit parity: OK`.
- Optional Node bridge audit refresh (historical; superseded for axios by the
  2026-04-25 override refresh above):
  - `npm audit --json` in `contrib/ledger-bridge/` reported 7 moderate /
    0 high advisories through the Ledger dependency tree at that point (`axios`
    SSRF/header injection plus `uuid` buffer-bounds handling).
  - The available npm "fix" paths remain semver-major downgrades or
    incompatible Ledger package changes, not a drop-in clean resolution for the
    current bridge tree.
- Risk disposition at that point:
  - The base Python install is expected to be clean again after the
    `python-dotenv` bump and lock refresh.
  - The optional Ledger bridge remains disabled by default, loopback-only, and
    bearer-token capable; its residual npm advisory exception remained
    documented until the 2026-04-25 axios override refresh narrowed the open
    exception to `uuid <14`.

### 2026-04-20 — v0.6.7 Ledger bridge subproject audit entry

- Scope: record the optional `contrib/ledger-bridge/` Node dependency surface
  introduced by the Ledger hardware signer candidate.
- Lockfile inspection after the compatible Ledger SDK bump:
  - `contrib/ledger-bridge/package-lock.json` has 127 package-lock entries
    (93 production, 34 dev).
  - All 127 resolved URLs are from `registry.npmjs.org`.
  - No lockfile package entries were missing `integrity`.
  - Root runtime dependencies are
    `@ledgerhq/context-module@1.16.0`,
    `@ledgerhq/device-management-kit@1.2.0`,
    `@ledgerhq/device-signer-kit-ethereum@1.14.0`,
    `@ledgerhq/device-transport-kit-node-hid@1.0.1`, and `rxjs`.
- Dependency remediation (v0.6.7 state; superseded for axios by the 2026-04-25
  override refresh above):
  - Bumped `@ledgerhq/context-module` from `1.14.1` to `1.16.0` and
    `@ledgerhq/device-signer-kit-ethereum` from `1.11.1` to `1.14.0`.
  - `npm test` and `npx tsc --noEmit` stayed green after the bump.
  - The bump removed the high-severity audit classification, but at v0.6.7
    release close residual moderate axios-derived findings remained because
    `@ledgerhq/device-management-kit@1.2.0` still depended on `axios@1.13.5`.
    The `v0.7.0` candidate later closes that axios exception with the 2026-04-25
    override refresh.
- Audit result:
  - `npm audit --json` in `contrib/ledger-bridge/` exited 1 with 6
    axios-related vulnerabilities (6 moderate, 0 high) through Ledger packages.
  - Advisories reported by npm for the vulnerable axios range include
    denial-of-service via `__proto__` prototype pollution, `NO_PROXY` SSRF, and
    metadata exfiltration via header injection.
  - At that point the compatible Ledger dependency tree did not offer a clean
    non-breaking resolution for `@ledgerhq/device-management-kit`,
    `@ledgerhq/device-transport-kit-node-hid`, or axios.
- Risk disposition:
  - The Ledger bridge is optional and disabled unless an operator installs and
    starts `contrib/ledger-bridge/` and sets `SHISAD_SIGNER_LEDGER_URL`.
  - The bridge listens on `127.0.0.1` only.
  - `/sign` and `/extract-key` can require a shared bearer token via
    `SHISAD_LEDGER_BRIDGE_BEARER_TOKEN` / `--bearer-token`, matched by the
    daemon's `SHISAD_SIGNER_LEDGER_BEARER_TOKEN`.
  - The bridge does not expose arbitrary URL-fetching routes; the axios surface
    is inside the Ledger DMK/context-module stack.
  - Acceptance is conditional on re-running `npm audit` during v0.6.7 release
    close and upgrading the Ledger SDK tree if a compatible fix exists.

### 2026-04-16 — v0.6.5 MCP/A2A release-close parity refresh

- Scope: refresh the dependency audit for the release-close candidate after
  the MCP/A2A interop lane introduced the direct `mcp` dependency groups and
  the new ASGI/SSE transitives they pull into the lock.
- Threat/risk read before update:
  - `mcp` is intentionally non-runtime by default in this release; it is
    declared in `dev` and the dedicated `interop` group so operators do not
    pick it up accidentally from the base install path.
  - The interop stack adds `httpx-sse`, `python-multipart`,
    `sse-starlette`, `starlette`, `uvicorn`, and `pyjwt` transitively.
    Release-close parity needs those packages called out explicitly so the
    audit doc matches the current lock surface.
- Execution and outcomes:
  - The maintainer-side supply-chain parity helper initially reported missing
    `mcp` entries for the `dev` and `interop` dependency groups.
  - The direct-dependency tables and selected lock inventory/edge-map rows
    below were refreshed to include the new interop surface plus the already
    published `pytest 9.0.3` / `pytest-asyncio 1.3.0` dev-toolchain state.

### 2026-04-03 — v0.6.0 release-close dependency audit remediation

- Scope: repair the release-time `pip-audit` path after the first OIDC publish
  run failed on the editable root package, refresh vulnerable locked packages
  (`aiohttp`, `Pygments`), and replace the broken `zizmor` container action in
  CI with the maintained `zizmor-action` path.
- Threat/risk read before implementation:
  - `publish.yml` was exporting `-e .` into the audit input, which makes
    `pip-audit --require-hashes` fail before it can evaluate the lock-derived
    dependency set.
  - Locked `aiohttp==3.13.3` and `Pygments==2.19.2` were behind currently
    available security fixes.
  - The pinned `zizmorcore/zizmor` action SHA started failing internally during
    its own Docker build because `ZIZMOR_VERSION` was no longer set in the
    action image build path.
- Execution and outcomes:
  - `uv lock --upgrade-package aiohttp --upgrade-package pygments` ->
    `Updated aiohttp v3.13.3 -> v3.13.5`, `Updated pygments v2.19.2 -> v2.20.0`.
  - `uvx pip-audit --require-hashes --disable-pip -r <(uv export --all-groups --frozen --format requirements.txt --no-emit-project)` ->
    `No known vulnerabilities found`.
  - `publish.yml` now audits the lock-derived requirements export with
    `--no-emit-project`, preserving hash enforcement while omitting the local
    editable root package that `pip-audit` cannot validate.
  - `ci.yml` now uses `zizmorcore/zizmor-action` pinned by SHA with explicit
    `version: v1.23.1` and `advanced-security: false`, keeping the workflow
    lint job blocking on actual findings while avoiding the broken upstream
    container-action build path.

### 2026-04-01 / 2026-04-09 — `cryptography` + `transformers` release-audit lane

- Scope:
  - 2026-04-01: review and apply a focused bump of direct runtime dependency
    `cryptography` from locked `45.0.7` to `46.0.6`; defer `Pygments`.
  - 2026-04-09: release-close remediation after the `v0.6.2` trusted-publish
    workflow audit failed on `cryptography 46.0.6` (`CVE-2026-39892`, fixed in
    `46.0.7`) and optional PromptGuard dependency `transformers 4.57.6`
    (`CVE-2026-1839`, fixed in `5.0.0rc3`).
- Behavioral contract impact: expected none; the repo uses `AESGCM`, `PBKDF2HMAC`, `hashes`, `InvalidTag`, `InvalidSignature`, and Ed25519 APIs only.
- Threat/risk read before implementation:
  - staying on `45.0.7` misses `CVE-2026-34073` fixed in `46.0.6`,
  - staying on `45.0.7` misses `CVE-2026-26007` fixed in `46.0.5`,
  - `46.0.0` is a major-version boundary, so compatibility validation must cover memory encryption and signature verification flows.
- Validation scope planned: targeted tests for the touched cryptography call sites, then static checks, then `uv run pytest tests/behavioral/ -q`.
- Execution and outcomes:
  - `uv lock --check` → success.
  - `uv lock --upgrade-package cryptography==46.0.6` → `Updated cryptography v45.0.7 -> v46.0.6`.
  - `uv run --group dev python -m pytest tests/unit/test_skills.py -k 'signature' -q` → `3 passed, 22 deselected`.
  - `uv run --group dev python -m pytest tests/unit/test_retrieval_routing.py tests/unit/test_memory_manager.py -q` → `17 passed`.
  - `uv run --group dev python -m pytest tests/integration/test_security_loop_core.py -q` → `3 passed`.
  - `uv run --group dev python -m ruff check src/ tests/ scripts/` → `All checks passed!`.
  - `uv run --group dev python -m mypy src/shisad/` → `Success: no issues found in 171 source files`.
  - `uv run --group dev python -m pytest tests/behavioral/ -q` → `41 passed, 6 skipped`.
  - 2026-04-09 remediation:
    - `uv lock --upgrade-package cryptography==46.0.7 --upgrade-package transformers==5.0.0rc3`
      refreshes the release lock with the first fixed versions seen by the
      publish workflow.
    - Validation scope: `tests/unit/test_promptguard_classifier.py`, focused
      cryptography/signer/evidence tests, static checks, then rerun the trusted
      publish workflow so the release gate itself re-executes the full bundle.

## 2026-04-01 Review Summary — `cryptography`

### Current state at review start

- Declared spec: `cryptography>=44.0,<46`
- Locked version: `45.0.7`
- Dependency class: direct runtime dependency
- Local usage surface:
  - `src/shisad/memory/ingestion.py`
  - `src/shisad/skills/signatures.py`

### Upstream release review

- Current target: `46.0.7`
- Target release date: `2026-03-25`
- Current locked release date: `2025-09-01`
- Provenance signal reviewed: PyPI shows verified project details and consistent upstream project ownership; useful but not sufficient alone for supply-chain trust.
- Relevant upstream fixes missed by staying on `45.0.7`:
  - `46.0.6`: fixes `CVE-2026-34073` in X.509 name-constraint verification for certain wildcard-DNS SAN leaf-certificate cases.
  - `46.0.5`: fixes `CVE-2026-26007`, where malformed binary-curve public keys could expose portions of a private key.
- Compatibility read before bump:
  - `46.0.0` removes Python 3.7 support and deprecates OpenSSL `<3.0`.
  - `46.0.0` removes legacy cipher classes from the main cipher module (`CAST5`, `SEED`, `IDEA`, `Blowfish`).
  - No local usage of those removed legacy APIs was found during pre-bump grep review.

### Decision

- Proceed with the `cryptography` bump to `46.0.7`.
- Applied lock update: `pyproject.toml` now declares `cryptography>=46.0.7,<47` and `uv.lock` resolves `46.0.7`.
- `Pygments` was deferred at the time and later upgraded to `2.20.0` in the
  2026-04-03 release-close remediation lane after the first release audit pass.
- Proceed with the PromptGuard dependency bump to `transformers 5.0.0rc3`.
  The local PromptGuard loader uses `AutoTokenizer` / `AutoConfig` with local
  ONNX inference only, so the expected compatibility surface is narrow and
  covered by the PromptGuard classifier contract tests.
- Widen the build-only `huggingface-hub` constraint to `>=1.3,<2` so the
  fixed `transformers` line resolves cleanly in `security-build`.

## Dependency Change-Control Plan

Going forward, dependency upgrades/additions should use this change-control
process by default.

### Review gate for upgrades

1. Identify whether the package is:
   - direct runtime,
   - optional runtime,
   - dev/test only,
   - transitive only.
2. Record the current locked version, proposed target version, and exact release dates.
3. Read the upstream changelog/release notes and classify the change:
   - security fix,
   - bug fix,
   - feature-only,
   - compatibility break / major release.
4. Review provenance signals before bumping:
   - PyPI verified details,
   - maintainer/owner continuity,
   - source/changelog linkage,
   - whether the release is old enough to pass the project cooldown preference.
5. Check local blast radius:
   - grep for direct imports/APIs used,
   - note removed/deprecated APIs in the new version,
   - identify the narrowest regression tests.
6. Upgrade with exact lockfile regeneration and review:
   - inspect `pyproject.toml` constraint changes,
   - inspect `uv.lock` artifact/hash changes for the package and any transitive churn,
   - reject unrelated lock churn unless intentionally required.
7. Validate in this order:
   - targeted tests,
   - static checks,
   - behavioral tests,
   - focused broader suites only when the blast radius warrants them.
8. Record the decision and residual risk in this audit/worklog.

### Review gate for new dependencies

New packages should meet a higher bar than upgrades:

1. Justify why stdlib or an existing dependency is insufficient.
2. Prefer mature packages with stable maintainership and clear release provenance.
3. Record the smallest acceptable version range in `pyproject.toml` and exact resolution in `uv.lock`.
4. Review new transitive dependencies introduced by the package.
5. Add or extend tests that cover both the intended capability and the failure mode if the dependency is missing or misbehaves.
6. Treat new runtime dependencies as security-relevant by default and document the attack-surface change.

## DEFERRALS

No open supply-chain deferrals as of 2026-06-03. The current Claude
adapter-chain advisory is recorded above as accepted runtime-npx adapter risk,
not as a new open deferral in this document.

### Closed Deferrals

| ID | Closure evidence | Residual risk | Closed in |
|---|---|---|---|
| SC-v0.7.0-ledger-uuid | Added an npm override for the optional Ledger bridge so Ledger SDK packages resolve patched `uuid@11.1.1`; regenerated `contrib/ledger-bridge/package-lock.json`; `npm audit --json`, `npm audit --omit=dev --json`, and `npm audit --omit=dev --audit-level=high` all exit 0. | Low. The bridge remains optional and disabled by default. Future Ledger SDK updates may remove the need for the override or change compatibility constraints; recheck during the next Ledger bridge dependency refresh. | 2026-05-07 Dependabot 21 remediation |

## Immediate Hardening Applied (2026-03-31)

The following low-friction controls were implemented immediately:

1. Pinned `opencode` adapter version:
   - `opencode-ai@1.3.10` in `src/shisad/coding/registry.py`.
2. Enforced frozen lock usage in CI dependency installs:
   - all `uv sync` calls in `.github/workflows/ci.yml` now include `--frozen`.
3. Pinned build backend dependency:
   - `[build-system].requires` now uses `hatchling==1.29.0` in `pyproject.toml`.
4. Enabled minimum-age cooldown for uv resolution:
   - CI `uv sync` calls now pass `--exclude-newer "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"`.

These changes improve lock determinism and reduce same-day package ingestion risk without changing user-facing runtime capabilities.

## Immediate Hardening Applied (2026-04-18)

The coding-agent ACP registry was refreshed after upstream package metadata
showed that the Claude adapter namespace moved:

1. Replaced deprecated Claude ACP adapter:
   - from `@zed-industries/claude-agent-acp@0.21.0`
   - to `@agentclientprotocol/claude-agent-acp@0.29.2`
   - npm `dist.shasum`: `a908d963ab3863fc83aa9b2ee27d77324149bed8`
   - npm `dist.integrity`:
     `sha512-Pg5sh8mxBsAmmKImlzgPYXGc+BW7xxXEC5/WWE+fQSPInj8ueRHinNxJxgIwRDwitlMs+NlMoVAGGgGMar92Bg==`
   - published: `2026-04-17T15:55:51.170Z`
   - rationale: the old `@zed-industries/claude-agent-acp` package is marked
     deprecated and no longer picks up Opus 4.7 fixes.
2. Refreshed Codex ACP adapter within its active namespace:
   - from `@zed-industries/codex-acp@0.9.5`
   - to `@zed-industries/codex-acp@0.11.1`
   - npm `dist.shasum`: `8a7d3a8995fa5dbcee96486e11b99702e7b30356`
   - npm `dist.integrity`:
     `sha512-My2VSlBtvJipJhImHjFDej2ut/p00QqOISRnZgLgLrSIzjgvdcQvAhaZviWj7XPhk4UIdIb0OoA+Lrls824uiQ==`
   - published: `2026-03-31T22:08:48.610Z`
   - rationale: `@agentclientprotocol/codex-acp` does not exist on npm and
     `@zed-industries/codex-acp` is not marked deprecated.
3. Left OpenCode unchanged at `opencode-ai@1.3.10`:
   - npm `dist.shasum`: `41a32d958fc2dbc8fce0fc6f42b50ed942bf8c90`
   - npm `dist.integrity`:
     `sha512-I0WgF6vrPIDK1XYknhNqbg5TsZwSEFX9l3T0SJkPuhUqhw1M5WsVM9Xb586KgOnJU8jJnjgZ8k+HP0p0PvaYSQ==`
   - published: `2026-03-31T13:32:31.472Z`
   - rationale: the newest `opencode-ai` package was modified on
     `2026-04-18`, is outside the Zed namespace migration, and was not needed
     for the Opus 4.7 fix.

Security checks recorded for the proposed adapter set:

- `npm audit --omit=dev --json` in a temporary npm project containing
  `@agentclientprotocol/claude-agent-acp@0.29.2`,
  `@zed-industries/codex-acp@0.11.1`, and `opencode-ai@1.3.10` reported
  `0` vulnerabilities.
- `npm audit signatures --json` for the installed temporary project reported
  no invalid or missing signatures.
- GitHub security-advisory queries for
  `agentclientprotocol/claude-agent-acp` and `zed-industries/codex-acp`
  returned no published advisories.
- GitHub Dependabot and code-scanning alert queries for `shisa-ai/shisad`
  returned no open alerts. Secret scanning is disabled on the repository, so no
  secret-scanning alert query was available.

## Follow-up Codex ACP Refresh (2026-04-28)

The Codex ACP adapter was refreshed again after ACP negotiation failed through
`@zed-industries/codex-acp@0.11.1` while direct Codex CLI execution completed
successfully.

1. Refreshed Codex ACP adapter within its active namespace:
   - from `@zed-industries/codex-acp@0.11.1`
   - to `@zed-industries/codex-acp@0.12.0`
   - npm `dist.shasum`: `3dc3328f7f34085249ff490bec319e93f6500132`
   - npm `dist.integrity`:
     `sha512-0d7gRzOiYTgDmIyh783mCcq50h3mdOg/TtKdLfBIghOLushpQRwhuLjKK8Q9hxZfNlPL0Ua56DoPjnsW8amf8g==`
   - published: `2026-04-24T13:47:02.567Z`
   - rationale: the active Codex ACP namespace published a bridge compatible
     with the current Codex CLI (`codex-cli 0.125.0`), and a default-registry
     ACP smoke completed through the normal adapter path.

Security checks recorded for the refreshed adapter set:

- `npm audit --omit=dev --json` in a temporary npm project containing
  `@agentclientprotocol/claude-agent-acp@0.29.2`,
  `@zed-industries/codex-acp@0.12.0`, and `opencode-ai@1.3.10` reported
  `0` vulnerabilities.
- `npm audit signatures --json` for the installed temporary project reported
  no invalid or missing signatures.

## Follow-up Codex ACP Refresh (2026-06-03)

The Codex ACP adapter was refreshed again after `@zed-industries/codex-acp@0.12.0`
failed before ACP initialization with current Codex configuration containing
`service_tier = "default"`. The adapter exit was reproduced locally; the newer
adapter completed a live ACP canary through the normal registry path.

1. Refreshed Codex ACP adapter within its active namespace:
   - from `@zed-industries/codex-acp@0.12.0`
   - to `@zed-industries/codex-acp@0.15.0`
   - npm `dist.shasum`: `7d3f9096c6b8575ecde0455692c7900691a195ef`
   - npm `dist.integrity`:
     `sha512-eAv7sGBeiYrYkOulF729nrM51szS7WIhBtugRj5wWq6csRKZUhAZfoUZlF8xUWdHPtOIzd/eT6MNG6gMHu6z0w==`
   - published: `2026-05-22T14:39:48.839Z`
   - rationale: the active Codex ACP namespace published a bridge compatible
     with the current Codex CLI/config surface; a default-registry live canary
     completed through `@zed-industries/codex-acp@0.15.0`.

Security checks recorded for the refreshed Codex adapter:

- `npm audit --omit=dev --json` in a temporary npm project containing only
  `@zed-industries/codex-acp@0.15.0` reported `0` vulnerabilities.
- `npm audit signatures --json` for the Codex-only temporary project reported
  no invalid or missing signatures.

Security checks recorded for the full current adapter set:

- `npm audit --omit=dev --json` in a temporary npm project containing
  `@agentclientprotocol/claude-agent-acp@0.29.2`,
  `@zed-industries/codex-acp@0.15.0`, and `opencode-ai@1.3.10` reported
  `3` moderate vulnerability rows, all through one advisory in the unchanged
  Claude adapter chain: `@agentclientprotocol/claude-agent-acp` ->
  `@anthropic-ai/claude-agent-sdk` -> `@anthropic-ai/sdk` advisory
  `GHSA-p7fg-763f-g4gf`.
- `npm audit signatures --json` for the full temporary project reported no
  invalid or missing signatures.

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
uv export --all-groups --frozen --format requirements.txt --no-emit-project
rg -o "source = \\{[^\\}]+\\}" uv.lock | sort | uniq -c
rg -c "^\\[\\[package\\]\\]" uv.lock
rg -n "hatchling|build-system" pyproject.toml uv.lock
rg -n "actions/checkout|setup-uv|upload-artifact|@v[0-9]+|uv sync" .github/workflows/ci.yml
rg -n "npx|@agentclientprotocol|@zed-industries|opencode-ai" src/shisad/coding/registry.py
sed -n '1,140p' docs/DEPLOY.md
```

## Dependency Map

### A. Python dependency chain summary

- `uv.lock` entries: `134` packages total.
- Third-party packages from registry: `133` (plus editable root package `shisad`).
- Registry source in lockfile: `133` entries from `https://pypi.org/simple`.
- Non-registry sources in lockfile: none (except local editable `shisad` root).

### B. Direct dependency declarations vs lock resolution

#### Runtime direct dependencies (`[project.dependencies]`)

| Package | Declared in `pyproject.toml` | Locked in `uv.lock` | Lock quality |
| --- | --- | --- | --- |
| `agent-client-protocol` | `==0.8.1` | `0.8.1` | Exact |
| `click` | `>=8.3.3,<9` | `8.4.2` | Range in spec, exact in lock |
| `cryptography` | `>=48.0.1,<49` | `48.0.1` | Range in spec, exact in lock |
| `fido2` | `>=2.1,<3` | `2.1.1` | Range in spec, exact in lock |
| `filelock` | `>=3.25,<4` | `3.25.2` | Range in spec, exact in lock |
| `loguru` | `>=0.7,<1` | `0.7.3` | Range in spec, exact in lock |
| `pydantic` | `>=2.10,<3` | `2.12.5` | Range in spec, exact in lock |
| `pydantic-settings` | `>=2.7,<3` | `2.14.2` | Range in spec, exact in lock |
| `python-dotenv` | `>=1.2.2,<2` | `1.2.2` | Range in spec, exact in lock |
| `qrcode` | `>=8.2,<9` | `8.2` | Range in spec, exact in lock |
| `pyyaml` | `>=6.0,<7` | `6.0.3` | Range in spec, exact in lock |
| `textguard[yara]` | `>=1.0,<2` | `1.0.0` | Range in spec, exact in lock |

#### Optional extras (`[project.optional-dependencies]`)

| Extra | Direct packages in extra | Lock status |
| --- | --- | --- |
| `assistant` | `textual`, `mcp`, `matrix-nio[e2e]`, `discord.py`, `python-telegram-bot`, `slack-bolt`, `slack-sdk` | All exact in lock; all declared as ranges |
| `chat` | `textual` | Exact in lock (`0.89.1`); declared as range |
| `promptguard` | `textguard[promptguard]` | Exact in lock through `textguard 1.0.0`; declared as range |

#### Dependency groups (`[dependency-groups]`)

| Group | Direct packages in group | Lock status |
| --- | --- | --- |
| `dev` | `mcp`, `numpy`, `pytest`, `pytest-asyncio`, `ruff`, `mypy`, `types-pyyaml`, `textual` | All exact in lock; all declared as ranges |
| `channels-runtime` | `matrix-nio[e2e]`, `discord.py`, `python-telegram-bot`, `slack-bolt`, `slack-sdk` | All exact in lock; all declared as ranges |
| `coverage` | `pytest-cov` | Exact in lock; declared as range |
| `interop` | `mcp` | Exact in lock; declared as range |
| `security-runtime` | `textguard[promptguard]`, `safetensors`, `sentencepiece` | All exact in lock; all declared as ranges |
| `security-build` | `textguard[promptguard]`, `torch`, `onnx`, `onnxscript`, `huggingface-hub`, `safetensors`, `sentencepiece` | All exact in lock; all declared as ranges |

`security-build` is intentionally heavier than `security-runtime`: it carries the
local PromptGuard download/export/model-pack toolchain and, on Linux, the
current `torch` build lane resolves CUDA-family packages in the lock. The live
daemon runtime does not require that group. After the v0.6.4 textguard
migration, `yara-python`, `onnxruntime`, and `transformers` are no longer
direct shisad declarations; they resolve transitively through `textguard[yara]`
or `textguard[promptguard]`. The v0.6.5 interop lane adds `mcp` as a direct
`dev`/`interop` dependency, with `httpx-sse`, `pyjwt`, `python-multipart`,
`sse-starlette`, `starlette`, and `uvicorn` resolving transitively through
that path.

### C. v0.8.1 local container candidate

- Both stages use the official Linux/amd64 Python 3.12 slim-bookworm manifest
  digest `sha256:72d3d75f2639ab82b34b29390ad3d6e0827c775befee94edda8e9976818f488d`.
- Runtime Python requirements are exported from `uv.lock` for the `assistant`
  extra and installed with required artifact hashes. The project is built as a
  wheel and installed non-editably into the final venv.
- `.dockerignore` admits only package/build inputs and excludes bytecode. The
  final stage does not contain `uv`, Hatchling, pytest, the test tree, or a
  source checkout. The clean-artifact journey checks the installed import path
  plus the absence of those build/test tools; the two-stage copy boundary
  excludes the checkout and test tree by construction.
- The final image runs as uid/gid `10001`, contains Tini, bwrap, pasta,
  iptables, and nsenter, and declares separate data and workspace volumes. It
  runs a bounded non-root namespace plus pasta-attachment preflight before the
  daemon and exposes bwrap-backed doctor rows only after that probe succeeds.
  It does not infer `CAP_NET_ADMIN` in this fixed non-root posture, so the
  current connect-path diagnostic is unavailable rather than overclaimed.
  Provider/channel secrets are runtime inputs, not image environment or build
  arguments.
- Residual build mutability remains: Debian packages are not version-pinned to
  a snapshot repository, and the exact `uv`/Hatchling builder declarations do
  not hash-pin all builder-only transitive wheels. Neither surface is copied as
  tooling into the runtime image.
- This is not a published image. There is no registry workflow, image SBOM,
  provenance attestation, signature, or documented signature-verification path
  yet; public docs therefore call it a local candidate only.

### D. Full upstream package inventory (all groups)

The full locked package set (third-party only) at snapshot time:

```text
agent-client-protocol==0.8.1
aiofiles==24.1.0
aiohappyeyeballs==2.6.1
aiohttp==3.14.3
aiohttp-socks==0.11.0
aiosignal==1.4.0
annotated-doc==0.0.4
annotated-types==0.7.0
anyio==4.12.1
atomicwrites==1.4.1
attrs==25.4.0
audioop-lts==0.2.2 ; python_full_version >= '3.13'
cachetools==5.5.2
certifi==2026.1.4
cffi==2.0.0
click==8.4.2
colorama==0.4.6 ; sys_platform == 'win32'
coverage==7.13.4
cryptography==48.0.1
cuda-bindings==13.2.0 ; sys_platform == 'linux'
cuda-pathfinder==1.5.1 ; sys_platform == 'linux'
cuda-toolkit==13.0.3.0 ; sys_platform == 'linux'
discord-py==2.6.4
fido2==2.1.1
filelock==3.25.2
flatbuffers==25.12.19
frozenlist==1.8.0
fsspec==2026.3.0
h11==0.16.0
h2==4.3.0
hf-xet==1.4.3 ; platform_machine == 'AMD64' or platform_machine == 'aarch64' or platform_machine == 'amd64' or platform_machine == 'arm64' or platform_machine == 'x86_64'
hpack==4.1.0
httpcore==1.0.9
httpx==0.28.1
httpx-sse==0.4.3
huggingface-hub==1.10.1
hyperframe==6.1.0
idna==3.15
iniconfig==2.3.0
jinja2==3.1.6
jsonschema==4.26.0
jsonschema-specifications==2025.9.1
librt==0.7.8 ; platform_python_implementation != 'PyPy'
linkify-it-py==2.0.3
loguru==0.7.3
markdown-it-py==4.0.0
markupsafe==3.0.3
matrix-nio==0.25.2
mcp==1.28.1
mdit-py-plugins==0.5.0
mdurl==0.1.2
ml-dtypes==0.5.4
mpmath==1.3.0
multidict==6.7.1
mypy==1.19.1
mypy-extensions==1.1.0
networkx==3.6.1
numpy==2.4.4
nvidia-cublas==13.1.1.3 ; sys_platform == 'linux'
nvidia-cuda-cupti==13.0.85 ; sys_platform == 'linux'
nvidia-cuda-nvrtc==13.0.88 ; sys_platform == 'linux'
nvidia-cuda-runtime==13.0.96 ; sys_platform == 'linux'
nvidia-cudnn-cu13==9.20.0.48 ; sys_platform == 'linux'
nvidia-cufft==12.0.0.61 ; sys_platform == 'linux'
nvidia-cufile==1.15.1.6 ; sys_platform == 'linux'
nvidia-curand==10.4.0.35 ; sys_platform == 'linux'
nvidia-cusolver==12.0.4.66 ; sys_platform == 'linux'
nvidia-cusparse==12.6.3.3 ; sys_platform == 'linux'
nvidia-cusparselt-cu13==0.8.1 ; sys_platform == 'linux'
nvidia-nccl-cu13==2.29.7 ; sys_platform == 'linux'
nvidia-nvjitlink==13.0.88 ; sys_platform == 'linux'
nvidia-nvshmem-cu13==3.4.5 ; sys_platform == 'linux'
nvidia-nvtx==13.0.85 ; sys_platform == 'linux'
onnx==1.22.0
onnx-ir==0.2.0
onnxruntime==1.24.4
onnxscript==0.6.2
packaging==26.0
pathspec==1.0.4
peewee==3.19.0
platformdirs==4.9.2
pluggy==1.6.0
propcache==0.4.1
protobuf==7.34.1
pycparser==3.0 ; implementation_name != 'PyPy'
pycryptodome==3.23.0
pydantic==2.12.5
pydantic-core==2.41.5
pydantic-settings==2.14.2
pygments==2.20.0
pyjwt==2.13.0
pytest==9.0.3
pytest-asyncio==1.3.0
pytest-cov==6.3.0
python-dotenv==1.2.2
python-multipart==0.0.32
python-olm==3.2.16
python-socks==2.8.0
python-telegram-bot==21.11.1
pywin32==311 ; sys_platform == 'win32'
pyyaml==6.0.3
qrcode==8.2
referencing==0.37.0
regex==2026.4.4
rich==14.3.2
rpds-py==0.30.0
ruff==0.15.0
safetensors==0.7.0
sentencepiece==0.2.1
setuptools==83.0.0
shellingham==1.5.4
slack-bolt==1.27.0
slack-sdk==3.40.0
sse-starlette==3.3.4
starlette==1.3.1
sympy==1.14.0
textguard==1.0.0
textual==0.89.1
tokenizers==0.22.2
torch==2.13.0
tqdm==4.67.3
transformers==5.5.3
triton==3.7.1 ; sys_platform == 'linux'
typer==0.24.1
types-pyyaml==6.0.12.20250915
typing-extensions==4.15.0
typing-inspection==0.4.2
uc-micro-py==1.0.3
unpaddedbase64==2.1.0
uvicorn==0.44.0 ; sys_platform != 'emscripten'
win32-setctime==1.2.0 ; sys_platform == 'win32'
yara-python==4.5.4
yarl==1.22.0
```

### E. Upstream edge map (who pulls what)

Immediate upstream edges derived from the lock export (`uv export --all-groups
--frozen --format requirements.txt --no-hashes --no-header`). The table omits
the common outer Darwin / non-`s390x` Linux / Windows resolution markers for
readability:

```text
agent-client-protocol==0.8.1
    # via shisad
aiofiles==24.1.0
    # via matrix-nio
aiohappyeyeballs==2.6.1
    # via aiohttp
aiohttp==3.14.3
    # via
    #   aiohttp-socks
    #   discord-py
    #   matrix-nio
aiohttp-socks==0.11.0
    # via matrix-nio
aiosignal==1.4.0
    # via aiohttp
annotated-doc==0.0.4
    # via typer
annotated-types==0.7.0
    # via pydantic
anyio==4.12.1
    # via
    #   httpx
    #   mcp
    #   sse-starlette
    #   starlette
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
click==8.4.2
    # via
    #   shisad
    #   typer
    #   uvicorn
colorama==0.4.6 ; sys_platform == 'win32'
    # via
    #   click
    #   loguru
    #   pytest
    #   qrcode
    #   tqdm
coverage==7.13.4
    # via pytest-cov
cryptography==48.0.1
    # via
    #   fido2
    #   pyjwt
    #   shisad
cuda-bindings==13.2.0 ; sys_platform == 'linux'
    # via torch
cuda-pathfinder==1.5.1 ; sys_platform == 'linux'
    # via cuda-bindings
cuda-toolkit==13.0.3.0 ; sys_platform == 'linux'
    # via torch
discord-py==2.6.4
fido2==2.1.1
    # via shisad
filelock==3.25.2
    # via
    #   huggingface-hub
    #   torch
flatbuffers==25.12.19
    # via onnxruntime
frozenlist==1.8.0
    # via
    #   aiohttp
    #   aiosignal
fsspec==2026.3.0
    # via
    #   huggingface-hub
    #   torch
h11==0.16.0
    # via
    #   httpcore
    #   matrix-nio
    #   uvicorn
h2==4.3.0
    # via matrix-nio
hf-xet==1.4.3 ; platform_machine == 'AMD64' or platform_machine == 'aarch64' or platform_machine == 'amd64' or platform_machine == 'arm64' or platform_machine == 'x86_64'
    # via huggingface-hub
hpack==4.1.0
    # via h2
httpcore==1.0.9
    # via httpx
httpx==0.28.1
    # via
    #   huggingface-hub
    #   mcp
    #   python-telegram-bot
httpx-sse==0.4.3
    # via mcp
huggingface-hub==1.10.1
    # via
    #   tokenizers
    #   transformers
hyperframe==6.1.0
    # via h2
idna==3.15
    # via
    #   anyio
    #   httpx
    #   yarl
iniconfig==2.3.0
    # via pytest
jinja2==3.1.6
    # via torch
jsonschema==4.26.0
    # via
    #   matrix-nio
    #   mcp
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
markupsafe==3.0.3
    # via jinja2
matrix-nio==0.25.2
mcp==1.28.1
mdit-py-plugins==0.5.0
    # via markdown-it-py
mdurl==0.1.2
    # via markdown-it-py
ml-dtypes==0.5.4
    # via
    #   onnx
    #   onnx-ir
    #   onnxscript
mpmath==1.3.0
    # via sympy
multidict==6.7.1
    # via
    #   aiohttp
    #   yarl
mypy==1.19.1
mypy-extensions==1.1.0
    # via mypy
networkx==3.6.1
    # via torch
numpy==2.4.4
    # via
    #   ml-dtypes
    #   onnx
    #   onnx-ir
    #   onnxruntime
    #   onnxscript
    #   transformers
nvidia-cublas==13.1.1.3 ; sys_platform == 'linux'
    # via
    #   cuda-toolkit
    #   nvidia-cudnn-cu13
    #   nvidia-cusolver
nvidia-cuda-cupti==13.0.85 ; sys_platform == 'linux'
    # via cuda-toolkit
nvidia-cuda-nvrtc==13.0.88 ; sys_platform == 'linux'
    # via cuda-toolkit
nvidia-cuda-runtime==13.0.96 ; sys_platform == 'linux'
    # via cuda-toolkit
nvidia-cudnn-cu13==9.20.0.48 ; sys_platform == 'linux'
    # via torch
nvidia-cufft==12.0.0.61 ; sys_platform == 'linux'
    # via cuda-toolkit
nvidia-cufile==1.15.1.6 ; sys_platform == 'linux'
    # via cuda-toolkit
nvidia-curand==10.4.0.35 ; sys_platform == 'linux'
    # via cuda-toolkit
nvidia-cusolver==12.0.4.66 ; sys_platform == 'linux'
    # via cuda-toolkit
nvidia-cusparse==12.6.3.3 ; sys_platform == 'linux'
    # via
    #   cuda-toolkit
    #   nvidia-cusolver
nvidia-cusparselt-cu13==0.8.1 ; sys_platform == 'linux'
    # via torch
nvidia-nccl-cu13==2.29.7 ; sys_platform == 'linux'
    # via torch
nvidia-nvjitlink==13.0.88 ; sys_platform == 'linux'
    # via
    #   cuda-toolkit
    #   nvidia-cufft
    #   nvidia-cusolver
    #   nvidia-cusparse
nvidia-nvshmem-cu13==3.4.5 ; sys_platform == 'linux'
    # via torch
nvidia-nvtx==13.0.85 ; sys_platform == 'linux'
    # via cuda-toolkit
onnx==1.22.0
    # via
    #   onnx-ir
    #   onnxscript
onnx-ir==0.2.0
    # via onnxscript
onnxruntime==1.24.4
    # via textguard
onnxscript==0.6.2
packaging==26.0
    # via
    #   huggingface-hub
    #   onnxruntime
    #   onnxscript
    #   pytest
    #   transformers
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
protobuf==7.34.1
    # via
    #   onnx
    #   onnxruntime
pycparser==3.0 ; implementation_name != 'PyPy'
    # via cffi
pycryptodome==3.23.0
    # via matrix-nio
pydantic==2.12.5
    # via
    #   agent-client-protocol
    #   mcp
    #   pydantic-settings
    #   shisad
pydantic-core==2.41.5
    # via pydantic
pydantic-settings==2.14.2
    # via
    #   mcp
    #   shisad
pygments==2.20.0
    # via
    #   pytest
    #   rich
pyjwt==2.13.0
    # via mcp
pytest==9.0.3
    # via
    #   pytest-asyncio
    #   pytest-cov
pytest-asyncio==1.3.0
pytest-cov==6.3.0
python-dotenv==1.2.2
    # via pydantic-settings
python-multipart==0.0.32
    # via mcp
python-olm==3.2.16
    # via matrix-nio
python-socks==2.8.0
    # via aiohttp-socks
python-telegram-bot==21.11.1
pywin32==311 ; sys_platform == 'win32'
    # via mcp
pyyaml==6.0.3
    # via
    #   huggingface-hub
    #   shisad
    #   transformers
qrcode==8.2
    # via shisad
referencing==0.37.0
    # via
    #   jsonschema
    #   jsonschema-specifications
regex==2026.4.4
    # via transformers
rich==14.3.2
    # via
    #   textual
    #   typer
rpds-py==0.30.0
    # via
    #   jsonschema
    #   referencing
ruff==0.15.0
safetensors==0.7.0
    # via transformers
sentencepiece==0.2.1
setuptools==83.0.0
    # via torch
shellingham==1.5.4
    # via typer
slack-bolt==1.27.0
slack-sdk==3.40.0
    # via slack-bolt
sse-starlette==3.3.4
    # via mcp
starlette==1.3.1
    # via
    #   mcp
    #   sse-starlette
sympy==1.14.0
    # via
    #   onnx-ir
    #   onnxruntime
    #   torch
textguard==1.0.0
    # via shisad
textual==0.89.1
tokenizers==0.22.2
    # via transformers
torch==2.13.0
tqdm==4.67.3
    # via
    #   huggingface-hub
    #   transformers
transformers==5.5.3
    # via textguard
triton==3.7.1 ; sys_platform == 'linux'
    # via torch
typer==0.24.1
    # via
    #   huggingface-hub
    #   transformers
types-pyyaml==6.0.12.20250915
typing-extensions==4.15.0
    # via
    #   aiosignal
    #   anyio
    #   huggingface-hub
    #   mcp
    #   mypy
    #   onnx
    #   onnx-ir
    #   onnxscript
    #   pydantic
    #   pydantic-core
    #   pytest-asyncio
    #   referencing
    #   starlette
    #   textual
    #   torch
    #   typing-inspection
typing-inspection==0.4.2
    # via
    #   mcp
    #   pydantic
    #   pydantic-settings
uc-micro-py==1.0.3
    # via linkify-it-py
unpaddedbase64==2.1.0
    # via matrix-nio
uvicorn==0.44.0 ; sys_platform != 'emscripten'
    # via mcp
win32-setctime==1.2.0 ; sys_platform == 'win32'
    # via loguru
yara-python==4.5.4
    # via textguard
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

3. **Build backend dependency pinning**
   - `build-system.requires` is now explicitly pinned to `hatchling==1.29.0`.

4. **CI lock consistency on install**
   - CI now runs `uv sync --frozen ...` across dependency-install steps.

5. **Minimum-age dependency cooldown (uv)**
   - CI resolution now uses a rolling 7-day cutoff timestamp via `--exclude-newer "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"`.

### Partially locked / weak points

1. **`pyproject.toml` direct dependency specs are mostly ranges**
   - Only 1 direct runtime dep is exact-pinned (`agent-client-protocol`).
   - Remaining direct deps and group deps are range-pinned and rely on `uv.lock` for exactness.

2. **Runtime npm adapter path is not fully immutable**
   - `src/shisad/coding/registry.py` uses `npx` at runtime.
   - `claude`, `codex`, and `opencode` adapters now all include explicit package versions.
   - None of these runtime npm resolves are hash-pinned in-repo.

3. **Some workflow tooling still depends on upstream registries at run time**
   - GitHub Actions references are SHA-pinned, but that does not by itself make
     every action internally immutable if it downloads tools or images at run
     time.
   - `ci.yml` now pins `zizmor-action` by SHA and requests an exact
     `zizmor` version (`v1.23.1`), which materially reduces that drift for the
     workflow-linting lane.
   - Remaining CI/release jobs still depend on external registries (PyPI,
     GitHub Container Registry) as an accepted operational tradeoff.

4. **Bootstrap/install path includes mutable upstream installers**
   - `docs/DEPLOY.md` bootstrap includes:
     - `apt-get install ...` with no package version pinning.
     - `curl -LsSf https://astral.sh/uv/install.sh | sh`.
   - This is common operationally but is not reproducible/immutable supply chain by default.

5. **Local container build is only partially reproducible**
   - The Python base is digest-pinned and runtime Python artifacts are selected
     from `uv.lock` with hashes.
   - Debian runtime packages and builder-only transitive packages still resolve
     from mutable upstream indexes at build time.
   - No registry image is published, so image signing, registry provenance,
     image SBOM attachment, and consumer verification are not yet implemented.

### Explicitly accepted risk

1. **Python interpreter version pinning**
   - Project metadata allows `requires-python = ">=3.12"`.
   - `.python-version` pins major/minor (`3.12`) but not patch.
   - This audit treats interpreter patch-level drift as an accepted, lower-priority risk per project stance.

## Controls Review

| Control | Status | Notes |
| --- | --- | --- |
| Lockfile committed | Yes | `uv.lock` committed and used in all workflows |
| Frozen install enforced | Yes | `uv sync --frozen` in all CI jobs |
| Age gate enforced | Yes | `--exclude-newer P7D` in all CI jobs |
| Hashes enforced at install surface | Yes | `uv.lock` records artifact hashes; CI uses `--frozen` |
| Build scripts deny-by-default | N/A | Python ecosystem; no install scripts in dependency chain |
| GitHub Actions pinned by SHA | Yes | All actions pinned to immutable commit SHAs; `zizmor-action` refreshed at v0.6.0 release-close |
| Release workflows avoid attacker-controlled triggers | Yes | `publish.yml` uses `workflow_dispatch` only |
| Workflow inputs sanitized before shell execution | Yes | Tag input compared via shell variable, not interpolated |
| Publish environment requires approval | Yes | `pypi-publish` GitHub Environment with required reviewers |
| Workflow linting (zizmor) | Yes | `zizmor-action` job runs on push + PR with exact `zizmor` version input (v0.6.0 release-close) |
| Dependency review in CI | Yes | `dependency-review-action` runs on PRs (v0.5.3) |
| SBOM / attestation | Yes | SPDX SBOM generation with explicit workflow-artifact upload + build provenance attestation in `publish.yml` (v0.5.3; SBOM upload path refreshed in v0.7.1) |
| Lockfile drift guard | Yes | `uv lock --check` as early CI gate (v0.5.3) |
| Trusted publishing (OIDC) | Yes | PyPI OIDC trusted publisher configured (v0.5.3) |
| Top-level permissions hardening | Yes | CI defaults to `contents: read` and expands only per job where needed (v0.6.0 release-close) |
| Container base digest | Yes (candidate) | Both image stages pin the reviewed Linux/amd64 Python manifest digest |
| Container runtime Python lock/hashes | Yes (candidate) | `uv.lock` export plus `--require-hashes`; final wheel install is non-editable |
| Container isolation readiness | Yes (candidate) | Non-root startup probe exercises namespace creation plus real pasta attachment before bwrap-backed doctor rows become available |
| Container OS/build-tool transitive pinning | Partial | Debian packages and builder-only transitive wheels remain index-resolved |
| Container registry signing/attestation | No | No image is published; required before an official-image claim |

## Minimum-Age Controls (uv + pip fallback note)

- **Implemented now (uv):**
  - CI now applies:

```bash
uv sync --exclude-newer "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" --frozen ...
```

  - This gives a rolling cooldown window for newly published versions without hardcoding a stale date.

- **pip fallback reminder (absolute timestamp model):**
  - pip uses `--uploaded-prior-to <timestamp>` / `PIP_UPLOADED_PRIOR_TO`.
  - Because that value is absolute, do not hardcode a static date in scripts.
  - Generate it dynamically per run to avoid manual reset drift, for example:

```bash
export PIP_UPLOADED_PRIOR_TO="$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"
python -m pip install -r requirements.txt
```

## CI / Workflow Coverage Gaps (Dedicated Lane)

Current GitHub Actions coverage is useful but not complete for supply-chain assurance. Treat this as a distinct improvement lane:

1. Pin all third-party actions to immutable commit SHAs.
2. Add a workflow guard that fails when lockfile or dependency policy drifts unexpectedly.
3. Add dependency-review / advisories checks for dependency PRs.
4. Maintain release-path checks (attestation/SBOM) and add hardware-backed or
   container-image signing when those release surfaces are introduced.
5. Add a periodic “supply-chain hygiene” job to emit inventory diffs and newly introduced package alerts.

## Findings

1. **Runtime npx adapter execution is lockable via env var** (CLOSED v0.5.3)
   - Evidence: `src/shisad/coding/registry.py` supports
     `SHISAD_REQUIRE_LOCAL_ADAPTERS=1` which replaces `npx` commands with
     bare binary names requiring pre-installed adapters on `$PATH`.
   - Risk: Low when lockdown is enabled. Default mode still uses `npx` with
     pinned versions for ease of use.
   - Residual: operators must opt in via the env var; default remains `npx`.

2. **Dependency audit runs at release time** (CLOSED v0.5.3; refreshed v0.6.0)
   - Evidence: `publish.yml` now runs `pip-audit` against the lock-derived
     requirements export with `--no-emit-project` and exports a full dependency
     tree snapshot as an artifact on every release.
   - Risk: Low. Dependabot handles reactive CVE alerts between releases.
   - Residual: no automated diff against previous release's tree (compare
     artifacts manually or add a diff step later).

3. **No internal package mirror/proxy**
   - Evidence: All CI and local resolution goes directly to pypi.org and
     npm registry.
   - Risk: Low at current scale. Acceptable while the project is small.
   - Recommended action: Evaluate when org infrastructure supports it.
     Deferred to post-v1.0.

## Prioritized Hardening Plan

### Priority 0 (fast, high-value) — CLOSED (v0.5.3)

1. ~~Pin GitHub Actions to immutable commit SHAs.~~ Done.
2. ~~Add explicit lock/policy drift guard jobs for dependency metadata.~~ Done (`uv lock --check` gate).
3. ~~Keep the uv cooldown and modernize syntax.~~ Done (`--exclude-newer P7D`).
4. ~~Add top-level `permissions: read-all` to CI workflow.~~ Superseded by narrower default `contents: read` plus job-local expansion at v0.6.0 release-close.
5. ~~Add dependency-review action for PRs.~~ Done.
6. ~~Add zizmor workflow linting.~~ Done.

### Priority 1 (next release lane)

1. ~~Add a production mode that disallows live runtime `npx` registry fetches and requires preinstalled adapters.~~ Done (`SHISAD_REQUIRE_LOCAL_ADAPTERS=1`).
2. Define and document a standard "approved internal package mirror/proxy" pattern for Python and npm. (Deferred to post-v1.0.)
3. ~~Add a dependency-audit job that emits full package inventory and lock summary.~~ Done (runs in `publish.yml` at release time; Dependabot covers inter-release CVE alerts).

### Priority 2 (roadmap-aligned, medium term) — CLOSED (v0.5.3)

1. ~~Move release publishing to trusted publishing + provenance attestations.~~ Done (OIDC trusted publisher + `publish.yml`; build provenance attestation covers `dist/shisad-*` as of the v0.7.1 review refresh).
2. ~~Add release SBOM generation + build provenance attestation.~~ Done (SPDX SBOM generated by anchore/sbom-action and uploaded with actions/upload-artifact; artifact attestation via actions/attest-build-provenance). Hardware-backed release signing remains future work (`PF.42`).
3. ~~Pin the local container candidate's base image by digest.~~ Done for the
   v0.8.1 F5 Linux/amd64 candidate. Registry publication remains future and
   requires image SBOM/provenance plus signature verification before an
   official-image claim.

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

- Python package supply chain is strong at the lockfile layer and now also
  at the CI/release layer after the v0.5.3 hardening pass plus the v0.6.0
  release-close refresh.
- All CI actions are SHA-pinned, GITHUB_TOKEN is read-only by default,
  dependency review and workflow linting are active, and the publish path
  uses OIDC trusted publishing with SBOM and attestations.
- The runtime npx adapter surface is now lockable via
  `SHISAD_REQUIRE_LOCAL_ADAPTERS=1`.
- Codex ACP runtime adapter provenance is current for
  `@zed-industries/codex-acp@0.15.0`; the full current coding-adapter set still
  carries `3` moderate npm vulnerability rows through one advisory in the
  unchanged Claude adapter chain and remains part of the accepted runtime-npx
  adapter risk.
- Bootstrap/installer paths (apt-get, curl-pipe-sh) remain mutable but are
  operationally standard and accepted risk at this scale.
- The v0.8.1 local image candidate improves consumer reproducibility through a
  digest-pinned base and hash-locked Python runtime, but Debian/build-only
  resolution remains partially mutable and the image is neither published nor
  signed.

## Decision Summary

This repo is **baseline-hardened with a small set of accepted operational
risks**. The v0.5.3 hardening pass, the v0.6.0 release-close refresh, and the
2026-06-03 Codex ACP adapter evidence refresh closed the immediate
CI/release-path and Codex adapter provenance gaps. The current Claude
adapter-chain advisory is recorded as accepted runtime-npx adapter risk rather
than an open deferral. Remaining open items (periodic hygiene inventory diffs,
internal package mirror/proxy, external GitHub/PyPI release environment audits,
hardware-backed release signing, and container-image publication/signing) are lower
priority or release-close/future-surface work with documented deferral targets.
