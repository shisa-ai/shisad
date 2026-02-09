rule tool_spoofing {
  meta:
    description = "M1 baseline rule"
  strings:
    // pattern: <\s*(use_tool|tool_call|function_call)
  condition:
    true
}
