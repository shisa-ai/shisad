# Skill Revocation Runbook (M6.6.4)

## 1. Revocation triggers

Revoke a skill when:
- malicious behavior indicators are confirmed
- provenance/signature trust is lost
- capability scope changes violate policy
- maintainer compromise or dependency confusion is suspected

## 2. Review current state

```bash
shisad status
shisad doctor check --component skills
shisad skill list
shisad dashboard skill-provenance --limit 200
shisad dashboard alerts --limit 200
```

Confirm that the `skills` status is `ok`, then collect the skill name, current
version, and recent security findings. A `corrupt` or `unsupported_schema`
inventory is retained in place and skill activation, revocation, listing, and
runtime authorization fail closed; static skill review remains available.

Restore `skills/inventory.json` from a trusted backup, or remove it only after
verifying that no skills should remain active, then restart shisad. Do not edit
the checksum envelope by hand.

## 3. Revoke

```bash
shisad skill revoke <skill_name> --reason security_revoke
```

Expected outcome:
- skill state transitions to `revoked`
- the owner-only inventory snapshot is durably published before the runtime tool is unregistered
- `SkillRevoked` audit event emitted

## 4. Contain and clean up

- terminate or lockdown sessions relying on revoked skill
- disable scheduled tasks that depend on revoked capability
- remove/replace affected skill artifacts via approved deployment workflow

## 5. Notify

Notify affected operators/users:
- why revoked
- impact scope
- replacement guidance (if any)

## 6. Verify

```bash
shisad doctor check --component skills
shisad skill list
shisad dashboard audit --search "SkillRevoked" --limit 100
```

Confirm revoked skill is no longer active in runtime authorization paths.
