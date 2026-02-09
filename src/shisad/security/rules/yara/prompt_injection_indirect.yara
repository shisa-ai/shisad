rule prompt_injection_indirect {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /disregard\s+all\s+rules/i
  condition:
    $a
}
