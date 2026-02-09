rule prompt_injection_direct {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /ignore\s+previous\s+instructions/i
  condition:
    $a
}
