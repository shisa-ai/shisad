# Supply Chain Analysis: LiteLLM, Adjacent Incidents, and shisad

*Created: 2026-03-25*  
*Updated: 2026-04-29 (v0.7.1 ACP/release-provenance refresh)*
*Status: Draft*  
*Snapshot basis: LiteLLM incident facts as of 2026-03-25; shisad current-state
sections refreshed through the v0.7.1 C2 review-refresh target.*

This note reviews the LiteLLM supply-chain compromise disclosed on March 24, 2026, maps the broader attack patterns that matter for AI-agent systems, and evaluates shisad's own supply-chain posture.

Related:
- Security model: `docs/SECURITY.md`
- Security case studies: `docs/analysis/ANALYSIS-security-casestudies.md`
- Skill-registry attack research: private research archive
- Signatures and integrity analysis: internal signatures/integrity notes
- Future supply-chain hardening backlog: `docs/ROADMAP.md`

---

## Executive Summary

- The LiteLLM incident is a publish-path compromise, not just a "bad dependency" story. The attacker got malicious packages onto PyPI outside the expected release path, and `litellm==1.82.8` escalated the impact by using a `.pth` file that executed on every Python startup.
- As of **March 24, 2026**, LiteLLM maintainers said the compromise affected `1.82.7` and `1.82.8`, that those packages were removed, that maintainer accounts were rotated, and that their current attribution is compromise via the Trivy dependency used in their CI/CD scanning workflow. That attribution is still the maintainer team's evolving explanation, not an independently closed postmortem.
- For shisad, the most important lesson is that "supply chain" is bigger than `pip install`: it includes Python packages, npm-delivered coding-agent adapters, CI actions, signed self-mod bundles, future container images, and any remote tool discovery path.
- shisad already has some strong patterns in the skill and self-modification lanes: manifest validation, pinned dependency metadata, signature checks, review-on-update, rollback, revocation, and an OIDC/SBOM/attestation-based PyPI publish workflow. The main remaining gaps are external release-environment configuration audit, exact direct dependency pinning policy, runtime `npx` fetches, and the lack of an immutable signed container-image path.

---

## LiteLLM Incident: What Happened

### Dated facts

- On **March 24, 2026**, LiteLLM issue `#24512` reported that `litellm==1.82.8` on PyPI contained a malicious `litellm_init.pth` file that executed automatically at Python startup, without requiring `import litellm`.
- The same report documented broad credential and secret collection from environment variables, SSH keys, cloud credentials, Kubernetes configs, Docker configs, shell history, wallet files, and other host data, with exfiltration to `https://models.litellm.cloud/`.
- LiteLLM issue `#24518`, also opened on **March 24, 2026**, stated that:
  - compromised versions were `1.82.7` and `1.82.8`,
  - `1.82.7` embedded payload in `litellm/proxy/proxy_server.py`,
  - `1.82.8` added `litellm_init.pth`, making the payload trigger at interpreter startup,
  - GitHub releases stopped at `v1.82.6.dev1`, implying the malicious PyPI uploads did not come from the normal GitHub release flow,
  - maintainer accounts were rotated,
  - official LiteLLM Proxy Docker image users were reported as unaffected because that image pinned its dependencies.
- On the 2026-03-25 incident snapshot, the PyPI page for `litellm` showed
  `1.82.6` file metadata with "Uploaded using Trusted Publishing? No" and
  "Uploaded via: twine". That is not proof of root cause by itself, but it
  shows the upload path depended on account-scoped credentials rather than
  OIDC-bound trusted publishing.

### Why this attack was especially bad

1. **The payload ran before normal application logic.**
   `.pth` files are evaluated by Python during startup. That turns "install a package" into "run attacker code every time Python starts."

2. **The malicious publish path bypassed the expected release narrative.**
   The GitHub release trail and the PyPI package trail diverged. That is exactly the kind of split defenders need to detect.

3. **The exfiltration domain looked plausibly related.**
   `litellm.cloud` is close enough to `litellm.ai` to survive a casual glance, especially in logs or a hurried incident review.

4. **The blast radius included CI, containers, and production hosts.**
   The original report explicitly called out local machines, CI/CD pipelines, Docker containers, and production servers. AI infrastructure packages often sit in all four places.

### What the incident really teaches

- Locking versions helps with opportunistic drift, but it does **not** protect you if the exact version you install is malicious.
- Code review is necessary, but not sufficient. The publish path, signing path, registry path, and CI toolchain are part of the security boundary.
- Security tooling in CI is itself part of the supply chain. If your scanner, action, or helper is compromised, it can become the initial access point for your publish credentials.

---

## Related Attack Patterns

The LiteLLM case is one instance of a broader family:

| Pattern | Example | Why it matters for shisad |
| --- | --- | --- |
| Maintainer or publisher compromise | LiteLLM `1.82.7` / `1.82.8`, `ua-parser-js` | Publish credentials and package ownership are high-value targets. |
| Transitive dependency poisoning | `event-stream` / `flatmap-stream` | Review of only direct dependencies is insufficient. |
| Skill / extension marketplace poisoning | ClawdHub "What Would Elon Do?", Cline `2.3.0` / OpenClaw install path | In agent ecosystems, "package install" often means "prompt + tool execution," not just library code. |
| Mutable CI reference poisoning | `xygeni-action@v5` tag poisoning | Tags are not immutable trust anchors; commit SHAs or signed provenance matter. |
| Developer endpoint compromise -> repo/package compromise | ForceMemo / GlassWorm-style repo rewrites | A compromised maintainer workstation can bypass normal repo trust signals. |
| Security-tooling compromise in CI | LiteLLM maintainer's current Trivy-in-CI attribution | "Defensive" tooling must be treated as privileged code, not as inherently trustworthy. |

The repo already tracks many adjacent case studies in `docs/analysis/ANALYSIS-security-casestudies.md`, especially:
- ClawdHub skill-registry poisoning
- Clinejection / unauthorized CLI publish
- OpenClaw ecosystem malware and skill marketplace abuse

---

## shisad's Supply Chain Surface

### 1. Python runtime dependencies

Current state:
- `pyproject.toml` uses a mix of exact pins and wide version ranges.
- `uv.lock` exists and records exact resolved versions plus distribution hashes.

Good:
- We do have a lockfile.
- `agent-client-protocol` is exact-pinned to `0.8.1`.

Gap:
- Most direct dependencies are still ranged (`>=...,<...`) rather than exact-pinned in `pyproject.toml`.
- That means the lockfile, not the project metadata, is carrying most of the reproducibility burden.

Assessment:
- Better than unconstrained `pip install`, but not yet a "release provenance is fully pinned" story.

### 2. Optional dependency groups

Current state:
- Dev, coverage, security-runtime, and channels-runtime groups are declared in `pyproject.toml` with ranges.

Good:
- They will resolve through `uv.lock` when synced from the locked project state.

Gap:
- These groups still enlarge the supply-chain surface significantly, especially the channel stack.
- The more optional surfaces we enable, the more important it becomes to treat the lockfile as mandatory release input.

### 3. Coding-agent adapters from npm

Current state:
- `src/shisad/coding/registry.py` pins:
  - `@agentclientprotocol/claude-agent-acp@0.29.2`
  - `@zed-industries/codex-acp@0.12.0`
  - `opencode-ai@1.3.10`

Good:
- Claude, Codex, and OpenCode ACP adapter commands are exact-pinned.
- The deprecated `@zed-industries/claude-agent-acp` namespace has been replaced
  with the active `@agentclientprotocol/claude-agent-acp` package.

Gap:
- The adapter code is still fetched via `npx` at runtime.
- There is no lockfile, vendored adapter tarball, or internal npm mirror for
  the runtime ACP adapter fetch path. The Ledger bridge has its own
  `contrib/ledger-bridge/package-lock.json`, but that does not lock these
  adapter packages.

Assessment:
- This is one of the clearest current supply-chain risks in the repo. In production terms, "run `npx` against the public registry at execution time" is not a strong trust model.

### 4. Skill bundles and admin self-modification artifacts

Current state:
- Skill manifests require pinned dependency versions (`==x.y.z`), `sha256:` digests, and prefixed signatures.
- `SkillPolicy.require_signature_for_auto_install=True` and `require_review_on_update=True`.
- Admin self-mod artifacts require signed `manifest.json` files and per-file hash validation.
- Rollback and revocation runbooks already exist.

Good:
- This is the strongest current supply-chain lane in shisad.
- The design assumes that third-party skills and behavior packs are untrusted until reviewed and signature-verified.
- Manifested capabilities, dependency metadata, and revocation are all first-class.

Gap:
- `config/selfmod/allowed_signers` is an empty operator-populated trust store by default. That is honest and safe, but it means the trust anchor only exists after operator setup.
- M6 closes the local skill-manifest tool-surface integrity gap (declared-tool schema hashes now persist across install/re-registration, and local tool metadata goes through dedicated tool-surface analysis), but multi-engine scanning and remote-tool discovery hardening are still future work.

Assessment:
- Strong model, stronger after the local M6 tool-surface hardening pass, but still partial overall and operator configuration is still required.

### 5. Release pipeline and publish provenance

Current state:
- `.github/workflows/publish.yml` is an in-repo, manually dispatched release
  workflow that checks the tag/version match, verifies `uv.lock`, runs release
  validation, builds artifacts, runs `twine check`, runs `pip-audit`, exports a
  dependency snapshot, generates an SPDX SBOM, uploads the SBOM as an explicit
  workflow artifact, and uploads release artifacts.
- The publish job uses the `pypi-publish` GitHub Environment with
  `id-token: write` and `attestations: write`, generates build provenance via
  `actions/attest-build-provenance`, and publishes through
  `pypa/gh-action-pypi-publish`.
- The publish workflow pins GitHub Actions by full commit SHA.

Good:
- OIDC trusted publishing, release SBOM generation and workflow-artifact
  upload, provenance attestation, lockfile verification, and release validation
  are visible in-repo.

Gap:
- GitHub Environment reviewer settings and PyPI trusted-publisher bindings are
  external service configuration and must still be audited during release
  close.
- Hardware-backed release signing keys remain future work (`PF.42`).

Assessment:
- The release integrity model now has an in-repo PyPI workflow with core
  provenance controls. The remaining release-path risk is mostly external
  service configuration, hardware-backed signing, and future container-image
  provenance.

### 6. Container images

Current state:
- There are no `Dockerfile*` files in the repo today.
- The docs discuss pinned image digests, signed container images, and read-only base images as the desired future direction.

Good:
- The current repo does not yet have a live container-image supply chain to compromise.

Gap:
- We also do not yet have the immutable-image story the docs point toward.

Assessment:
- Lower current exposure, but this becomes critical as soon as containerized deployment is formalized.

### 7. Future remote tool discovery / MCP / A2A

Current state:
- shisad already recognizes that tool metadata and remote tool discovery must be treated as supply chain.
- Full MCP/A2A trust policy is future roadmap work.

Assessment:
- Correct threat model, not yet a finished control surface.

---

## What shisad Already Does Right

1. **Lockfile exists.**
   `uv.lock` records exact resolved artifacts and hashes for the Python dependency graph.

2. **Skill dependency metadata is stricter than the base Python project metadata.**
   Skill dependencies must be exact-pinned, digest-declared, and signature-declared.

3. **Unsigned or untrusted skills do not silently auto-install.**
   `SkillPolicy` defaults to requiring signatures for auto-install and requiring review on update.

4. **Self-modification artifacts are treated like signed control-plane artifacts.**
   `src/shisad/selfmod/manager.py` verifies signed `manifest.json`, validates file hashes, and supports rollback.

5. **Revocation and rollback are first-class.**
   `docs/runbooks/rollback.md` and `docs/runbooks/skill-revocation.md` already assume compromise and document containment.

6. **Some high-risk npm surfaces are at least version-pinned.**
   The Claude, Codex, and OpenCode ACP adapters are pinned to exact versions
   in the coding-agent registry.

---

## Where shisad Is Still Exposed

1. **Wide direct dependency ranges in `pyproject.toml`.**
   The repo is relying on `uv.lock` for determinism more than on exact project metadata.

2. **Runtime `npx` fetches.**
   Public-registry code is still being fetched at execution time for coding-agent adapters.

3. **No npm age gate for runtime adapter fetches.**
   Python dependency resolution uses a CI cooldown, but runtime `npx` adapter
   fetches do not yet have an equivalent in-repo age or mirror policy.

4. **Release provenance still depends on external service configuration.**
   The in-repo publish workflow uses OIDC trusted publishing, SBOM generation,
   and build provenance attestations, but GitHub Environment and PyPI
   trusted-publisher bindings remain outside the repository.

5. **No immutable image workflow yet.**
   Once container deployment becomes real, digest pinning and image signing need to become mandatory, not aspirational.

6. **Trust-store setup is operator-dependent.**
   The self-mod trust anchor is present as a mechanism, but not populated by default.

---

## How We Should Minimize These Issues

### 1. Treat `uv.lock` as the canonical release input

- Release builds should come from the locked dependency graph, not from fresh re-resolution.
- Lockfile diffs should be reviewed as security-relevant changes.
- For release packaging, the direct dependency surface should be as exact and predictable as practical.

### 2. Eliminate runtime registry fetches in production paths

- Do not rely on `npx` reaching the public npm registry at task execution time in production.
- Preinstall ACP adapters in the build environment, pin exact versions, and preferably source them from an internal mirror or vendored artifact set.
- Keep all ACP adapter pins under registry/test coverage while moving
  production deployments away from live public-registry `npx` fetches.

### 3. Use trusted publishing for public releases

- Prefer OIDC-based trusted publishing over long-lived PyPI or npm tokens.
- Separate build, sign, and publish roles.
- Make the publish step prove provenance rather than rely on credential possession alone.

### 4. Pin CI dependencies immutably

- Pin GitHub Actions by full commit SHA, not mutable tags.
- Keep untrusted PR execution isolated from release credentials and publish workflows.
- Never mix `pull_request_target`-style elevated CI with attacker-controlled code checkout.

### 5. Burn images, do not "heal" them in place

When shisad ships container images, the model should be:

- pin base images by digest, not tag
- build immutable release images
- sign them
- attach SBOM and provenance attestations
- if compromise is suspected, treat the image digest as burnt:
  - revoke trust in that digest
  - rotate any credentials exposed during its lifetime
  - rebuild from known-good inputs
  - redeploy a new digest

In other words: no mutable `latest`, no retagging compromised artifacts into "safe" ones, no patch-in-place trust model.

### 6. Keep the current skill/self-mod model strict

- Keep signatures and manifest validation mandatory for auto-install paths.
- Keep full-content review and rollback/revocation operational.
- Populate and rotate `allowed_signers` in real operator environments.

### 7. Minimize secrets in build and execution environments

- The LiteLLM payload went after env vars, SSH keys, cloud creds, Docker configs, shell history, and CI files because those are usually there.
- The best mitigation is to reduce what exists at all:
  - short-lived tokens
  - scoped credentials
  - no publish secrets on general-purpose runners
  - isolated build/publish environments

---

## Organizational Mitigations for Aggressive Exfiltration

The LiteLLM incident matters not just because a package was poisoned, but because the payload immediately tried to harvest anything reusable: env vars, cloud tokens, SSH material, Docker and Kubernetes configs, shell history, and local secrets. That shifts the question from "how do we stop every bad package?" to "how do we make a bad package find less to steal, and less of it worth stealing?"

### What helps quickly

- Put Python and npm installs behind an internal package endpoint instead of letting developer machines, CI, and production paths hit public registries directly.
- Out of the box, this is already possible with tools like AWS CodeArtifact upstream repositories / external connections and Google Artifact Registry remote repositories.
- The immediate win is a single choke point for caching, logging, emergency blocking, and "what did we actually pull?" review.
- **Inference from the vendor docs:** default proxy/cache behavior is not the same thing as a quarantine window. If we want a "stay 72 hours behind PyPI/npm" rule, that usually means separate `quarantine` and `approved` repositories plus an explicit promotion job, not just turning on upstream caching.
- A short lag window is still worth doing. It will not catch sleeper implants or quiet maintainer compromise that stays hidden for weeks, but it does reduce exposure to the same-day drive-by poisonings that now happen repeatedly.

### Reduce the value of developer-box secret theft

- The highest-leverage control is to stop keeping long-lived, reusable credentials on laptops and general-purpose CI runners.
- Prefer short-lived, federated credentials wherever possible:
  - AWS STS or assumed-role sessions instead of static access keys
  - Google Workload Identity Federation or service-account impersonation instead of exported service-account keys
  - GitHub Actions OIDC / PyPI Trusted Publishing instead of long-lived publish tokens in CI
- Prefer secret-manager or broker API retrieval over plaintext files and environment variables. Google explicitly recommends avoiding filesystem and environment-variable secret delivery because debug endpoints, dependency logging, and filesystem exposure routinely leak them.
- Keep publish credentials off ordinary dev boxes entirely where possible. Developers should request scoped session access; dedicated release jobs should publish using trusted identities, not copied tokens.

### Where hardware-backed local key storage helps, and where it does not

- Strongly encrypted local storage plus a hardware-backed or passkey-based unlock is still worth doing.
- Local workstation keystores help with at-rest protection:
  - macOS Keychain for local secrets and bootstrap material
  - Windows Credential Locker for Windows-native app credentials
  - OpenSSH `ed25519-sk` / `ecdsa-sk` keys for admin access and signing, where the device private key is non-exportable and can require touch or PIN verification
- This materially reduces risk from disk theft, backup leaks, casual file scraping, and post-mortem access to a turned-off box.
- It does **not** fully solve same-user malware. If a poisoned dependency runs after unlock, it can still read process environment, call local CLIs, or request tokens from local agents. At that point the main protections are short TTLs, narrow scope, audited retrieval, and per-use mediation.
- The safer pattern is: keep only bootstrap credentials locally, use those to unlock a broker, and mint short-lived session credentials into memory on demand.
- Memory-only storage is directionally right for session credentials with aggressive expiration. It is much less helpful for long-lived master secrets that a live implant can still dump once unlocked.
- If we build this ourselves, the HSM/KMS should protect the wrapping or signing key, while a secret manager or broker stores the secret payloads. HSM/KMS is a key-management primitive, not a general-purpose secret database.

### Easy things an org can build

- Promotion-based repository flow: public upstream -> quarantine repo -> approved repo. CI and production only install from approved; developers can opt into quarantine when they explicitly need to investigate or test.
- Local credential broker: after SSO plus passkey or hardware-key approval, issue a 15-60 minute token over a local socket or stdout path instead of writing it to `.env`, shell startup files, or other durable disk locations.
- Release-path isolation: keep low-trust scanning, dependency update automation, and untrusted PR execution away from the workflows that can publish artifacts or mint high-value tokens.
- Egress reduction for high-trust hosts: alert on new destinations from release runners, build hosts, and admin workstations. If a package suddenly starts talking to a lookalike domain, it should be visible quickly.
- Burn the endpoint if the payload ran with meaningful secrets available. For aggressive exfiltration malware, "clean and continue" is usually the wrong recovery model; rotate, revoke, rebuild from a known-good image, and then restore the minimum required access.

---

## Practical Follow-Ons for shisad

Short-term:
- Keep ACP adapter exact pins covered by registry tests while documenting
  whether production installs use preinstalled adapters, an internal mirror, or
  vendored artifacts.
- Write down the intended release/install rule for Python dependencies: whether the project commits to lockfile-only release installs, exact direct pins, or both.
- Document that production deployments should not rely on live public-registry `npx` fetches.
- Document operator guidance for internal package proxies, short-lived credentials, and "no durable secrets on dev/build/publish hosts" posture.

Medium-term:
- `PF.43` follow-up/audit: CI-based release publishing enforcement and
  external GitHub/PyPI environment settings
- `PF.42`: hardware-backed release signing keys
- `PF.70`: tool-surface supply-chain hardening bundle
- `PF.21`: no public skill marketplace until signed package policy, provenance attestation, allowlist governance, and rollback/revocation are concrete

This analysis does not materially change the roadmap. It mostly validates that the existing future backlog items are the right ones, and that the ACP adapter fetch path deserves more urgency than it may have looked to deserve before the LiteLLM incident.

---

## References

External:
- LiteLLM technical analysis issue `#24512`: <https://github.com/BerriAI/litellm/issues/24512>
- LiteLLM maintainer status issue `#24518`: <https://github.com/BerriAI/litellm/issues/24518>
- LiteLLM PyPI page and file metadata: <https://pypi.org/project/litellm/>
- StepSecurity CI/CD incidents tracker: <https://www.stepsecurity.io/incidents>
- PyPI trusted publishing: <https://docs.pypi.org/trusted-publishers/using-a-publisher/>
- PyPI trusted publishing security model: <https://docs.pypi.org/trusted-publishers/security-model/>
- PyPI attestations security model: <https://docs.pypi.org/attestations/security-model/>
- pip secure installs / hash-checking mode: <https://pip.pypa.io/en/stable/topics/secure-installs/>
- GitHub Actions OIDC guidance: <https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-cloud-providers>
- GitHub immutable releases: <https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases>
- AWS CodeArtifact upstream repositories: <https://docs.aws.amazon.com/codeartifact/latest/ug/repos-upstream.html>
- AWS CodeArtifact upstream fetch and retention behavior: <https://docs.aws.amazon.com/codeartifact/latest/ug/repo-upstream-behavior.html>
- Google Artifact Registry remote repositories for PyPI: <https://cloud.google.com/artifact-registry/docs/python/configure-remote-auth-pypi>
- AWS temporary security credentials (STS): <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html>
- Google Secret Manager best practices: <https://cloud.google.com/secret-manager/docs/best-practices>
- OpenSSH `ssh-keygen(1)` security-key support: <https://man.openbsd.org/OpenBSD-7.3/ssh-keygen.1>
- Apple keychain guidance: <https://developer.apple.com/library/archive/documentation/Security/Conceptual/cryptoservices/Introduction/Introduction.html>
- Windows Credential Locker guidance: <https://learn.microsoft.com/en-us/windows/apps/develop/security/credential-locker>
- Google Cloud KMS / HSM FAQ: <https://cloud.google.com/kms/docs/faq>

Internal:
- `docs/SECURITY.md`
- `docs/analysis/ANALYSIS-security-casestudies.md`
- private skill-registry research archive
- internal signatures/integrity notes
- `docs/ROADMAP.md`
