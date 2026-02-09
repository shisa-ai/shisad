rule masquerading_authority {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /i\s+am\s+(the\s+)?(developer|system)/i
  condition:
    $a
}
