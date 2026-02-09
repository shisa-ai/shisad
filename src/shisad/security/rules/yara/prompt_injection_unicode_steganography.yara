rule prompt_injection_unicode_steganography {
  meta:
    description = "M1 baseline rule"
  strings:
    // pattern: \u200b|\u200c|\u200d
  condition:
    true
}
