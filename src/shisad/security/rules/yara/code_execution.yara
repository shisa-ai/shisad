rule code_execution {
  meta:
    description = "M1 baseline rule"
  strings:
    // pattern: \b(eval|exec\(|subprocess\.)\b
  condition:
    true
}
