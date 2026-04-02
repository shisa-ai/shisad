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

If the operator needs a bounded cutover artifact before rollback, export the
current session first. These session lifecycle controls are operator/admin
surfaces; they are not available to unprivileged control peers:

```bash
shisad session export <session-id> /tmp/<session-id>.shisad-session.zip
```

Session archives are intentionally scoped to:
- persisted session state
- lockdown state
- transcript rows
- session checkpoints

They do **not** include evidence blobs, memory databases, or scheduler-global
state. Import validation is fail-closed on archive integrity/scope mismatch,
invalid ZIP payloads, oversized members, or oversized total archive contents.

## 3. Execute rollback

Session rollback path:
- call `session.rollback` with checkpoint ID for each affected session.
- checkpoint rollback restores the persisted session snapshot, including session
  mode and lockdown level when the checkpoint carries them.

Archive-assisted cutover path:
- import archive into a fresh session with `session.import`
- verify binding/mode/lockdown on the imported session
- if needed, run `session.rollback` against one of the imported checkpoint IDs
  to reapply the archived safe state before resuming work

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
- imported sessions remain bound to the original channel/user/workspace tuple
