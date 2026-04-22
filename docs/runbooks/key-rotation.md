# Memory Export + Key Rotation Runbook

## 1. When to run this

- Before scheduled key rotation
- Immediately after suspected memory/retrieval data exposure
- Before risky storage maintenance that should have a human-readable backup artifact

## 2. Preparation

- Ensure daemon health is stable:

  ```bash
  shisad status
  shisad audit verify
  ```

- Confirm low active write load if possible.
- Pick an export destination outside the active data dir, for example `/var/backups/shisad/`.

## 3. Export current memory

Canonical JSON export:

```bash
mkdir -p /var/backups/shisad
shisad memory export --format json > /var/backups/shisad/memory-$(date +%F).json
```

Optional CSV export for spreadsheet/audit review:

```bash
shisad memory export --format csv > /var/backups/shisad/memory-$(date +%F).csv
```

Confirm the export file is non-empty and parseable before continuing.

## 4. Execute rotation

Rotate with re-encryption (preferred):

```bash
shisad memory rotate-key
```

Fast rotation without re-encryption (emergency stopgap):

```bash
shisad memory rotate-key --no-reencrypt
```

## 5. Validation

Validate the audit trail and read-path health:

```bash
shisad dashboard audit --search "memory.rotate_key" --limit 50
shisad memory list --limit 20
```

Confirm:
- new active key ID emitted
- no decrypt failures on existing entries
- the exported backup artifact is retained with the change record / incident ticket

## 6. Post-rotation

- Record rotation in change log/ticket
- Revoke superseded key material per environment policy
- If emergency path used, schedule full re-encryption follow-up
