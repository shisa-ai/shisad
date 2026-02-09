rule command_injection {
  meta:
    description = "M1 baseline rule"
  strings:
    // pattern: \b(curl|wget|bash\s+-c|powershell)\b
  condition:
    true
}
