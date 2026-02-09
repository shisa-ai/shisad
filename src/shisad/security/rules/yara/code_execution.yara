rule code_execution {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /\b(eval|exec\(|subprocess\.)\b/i
  condition:
    $a
}
