# Skill Revocation Runbook (M6.6.4)

## 1. Revocation triggers

Revoke a skill when:
- malicious behavior indicators are confirmed
- provenance/signature trust is lost
- capability scope changes violate policy
- maintainer compromise or dependency confusion is suspected

## 2. Review current state

```bash
shisad skill list
shisad dashboard skill-provenance --limit 200
shisad dashboard alerts --limit 200
```

Collect skill name, current version, and recent security findings.

## 3. Revoke

```bash
shisad skill revoke <skill_name> --reason security_revoke
```

Expected outcome:
- skill state transitions to `revoked`
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
shisad skill list
shisad dashboard audit --search "SkillRevoked" --limit 100
```

Confirm revoked skill is no longer active in runtime authorization paths.
