rule tool_chaining_abuse {
  meta:
    description = "M1 baseline rule"
  strings:
    // pattern: tool\s*->\s*tool
  condition:
    true
}
