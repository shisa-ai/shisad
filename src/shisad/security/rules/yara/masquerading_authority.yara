rule masquerading_authority {
  meta:
    description = "M1 baseline rule"
  strings:
    // pattern: i\s+am\s+(the\s+)?(developer|system)
  condition:
    true
}
