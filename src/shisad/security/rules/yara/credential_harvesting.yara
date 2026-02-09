rule credential_harvesting {
  meta:
    description = "M1 baseline rule"
  strings:
    // pattern: send\s+(me\s+)?(your\s+)?(api\s+key|token|password)
  condition:
    true
}
