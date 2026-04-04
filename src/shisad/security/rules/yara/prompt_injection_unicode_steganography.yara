rule prompt_injection_unicode_steganography {
  meta:
    description = "M1 baseline rule"
  strings:
    // U+200B ZERO WIDTH SPACE, U+200C ZERO WIDTH NON-JOINER,
    // U+200D ZERO WIDTH JOINER, U+202E RIGHT-TO-LEFT OVERRIDE.
    $a = /​|‌|‍|‮/
  condition:
    $a
}
