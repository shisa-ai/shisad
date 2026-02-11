# Incident Response Runbook (M6.6.1)

## 1. Detection

Trigger sources:
- `dashboard.alerts` output (`shisad dashboard alerts`)
- Lockdown transitions (`LockdownChanged`)
- Exfiltration controls (`ProxyRequestEvaluated`, `ControlPlaneNetworkObserved`)
- Confirmation hygiene anomalies (`AnomalyReported` by `confirmation_analytics`)

## 2. Triage

Classify severity:
- `SEV-1`: confirmed active exfiltration or policy bypass attempt
- `SEV-2`: repeated blocked attempts, suspicious skill/runtime behavior
- `SEV-3`: isolated false positive or low-confidence anomaly

Initial triage commands:

```bash
shisad dashboard alerts --limit 200
shisad dashboard egress --limit 200
shisad dashboard audit --search "session_in_lockdown" --limit 200
```

## 3. Containment

For `SEV-1`/`SEV-2`, force lockdown immediately:

```bash
shisad session list
shisad policy explain --session <session_id>
```

Then via control API/automation:
- set affected sessions to `full_lockdown` (or `lockdown`) with reason tag
- revoke suspicious skills (`shisad skill revoke <skill_name> --reason incident_containment`)

## 4. Investigation

Collect audit evidence:

```bash
shisad dashboard audit --session <session_id> --limit 500
shisad dashboard audit --type ProxyRequestEvaluated --limit 500
shisad dashboard audit --type ToolRejected --limit 500
shisad audit verify
```

Capture:
- event IDs/timestamps
- reason codes and risk tiers
- pending confirmation state and leak-check metadata
- skill provenance timeline (`shisad dashboard skill-provenance`)

## 5. Recovery

After containment root cause is fixed:
- rollback impacted sessions/tasks as needed (see `rollback.md`)
- rotate encryption/credential material if exposure suspected (see `key-rotation.md`)
- keep heightened monitoring for at least one full day

## 6. Postmortem

Required write-up:
- timeline
- blast radius
- root cause + contributing factors
- controls that worked / gaps found
- concrete follow-up actions with owners and due dates
