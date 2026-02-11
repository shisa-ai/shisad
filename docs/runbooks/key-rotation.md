# Key Rotation Runbook (M6.6.3)

## 1. Rotation cadence

- Scheduled: at least every 90 days
- Emergency: immediately after suspected memory/retrieval data exposure

## 2. Preparation

- Ensure daemon health is stable:

```bash
shisad status
shisad audit verify
```

- Confirm low active write load if possible.

## 3. Execute rotation

Rotate with re-encryption (preferred):

```bash
shisad memory rotate-key
```

Fast rotation without re-encryption (emergency stopgap):

```bash
shisad memory rotate-key --no-reencrypt
```

## 4. Validation

Validate audit trail and memory reads:

```bash
shisad dashboard audit --search "memory.rotate_key" --limit 50
shisad memory list --limit 20
```

Confirm:
- new active key ID emitted
- no decrypt failures on existing entries

## 5. Post-rotation

- Record rotation in change log/ticket
- Revoke superseded key material per environment policy
- If emergency path used, schedule full re-encryption follow-up
