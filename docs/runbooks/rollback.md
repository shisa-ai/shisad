# Rollback Runbook (M6.6.2)

## 1. When to rollback

Rollback is required when:
- policy/config update causes widespread false rejects or unsafe allows
- a new skill release introduces high-risk behavior
- runtime regression impacts confirmation or control-plane enforcement

## 2. Choose rollback target

Identify safe checkpoint and affected sessions:

```bash
shisad dashboard audit --search "SandboxPreCheckpoint" --limit 200
shisad dashboard audit --search "SessionRolledBack" --limit 200
shisad session list
```

Prefer the most recent checkpoint before first bad event.

## 3. Execute rollback

Session rollback path:
- call `session.rollback` with checkpoint ID for each affected session.

Policy/config rollback path:
- restore known-good policy artifact
- restart daemon cleanly

Skill rollback path:
- revoke newly introduced skill
- reinstall prior known-good version (manifest-locked)

## 4. Verify rollback

Post-checks:

```bash
shisad status
shisad audit verify
shisad dashboard alerts --limit 100
shisad dashboard egress --limit 100
```

Confirm:
- no new critical alerts after rollback
- confirmation queue drains normally
- expected workflow utility restored
