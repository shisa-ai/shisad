rule data_exfiltration {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /exfiltrat(e|ion)|webhook/i
  condition:
    $a
}
