rule data_exfiltration {
  meta:
    description = "M1 baseline rule"
  strings:
    // pattern: exfiltrat(e|ion)|webhook
  condition:
    true
}
