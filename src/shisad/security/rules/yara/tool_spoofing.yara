rule tool_spoofing {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /<\s*(use_tool|tool_call|function_call)/i
  condition:
    $a
}
