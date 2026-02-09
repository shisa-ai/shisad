rule command_injection {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /\b(curl|wget|bash\s+-c|powershell)\b/i
  condition:
    $a
}
