rule tool_chaining_abuse {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /tool\s*->\s*tool/i
  condition:
    $a
}
