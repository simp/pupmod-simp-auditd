# A list parameter: an Array of entries, or a Hash of entry to an optional
# `ensure`, so `ensure => absent` can remove one.
type Auditd::EntryList = Variant[
  Array[String[1]],
  Hash[String[1], Struct[{ Optional['ensure'] => Enum['present', 'absent'] }]],
]
