rule capability_inflation {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /grant\s+yourself\s+permission/i
  condition:
    $a
}
