rule credential_harvesting {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /send\s+(me\s+)?(your\s+)?(api\s+key|token|password)/i
  condition:
    $a
}
