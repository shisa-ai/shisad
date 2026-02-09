rule prompt_injection_unicode_steganography {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /\x{200B}|\x{200C}|\x{200D}|\x{202E}/i
  condition:
    $a
}
