rule autonomy_abuse {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /autonomously\s+execute/i
  condition:
    $a
}
