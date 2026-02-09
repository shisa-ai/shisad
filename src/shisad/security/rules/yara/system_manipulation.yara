rule system_manipulation {
  meta:
    description = "M1 baseline rule"
  strings:
    $a = /reveal\s+system\s+prompt/i
  condition:
    $a
}
