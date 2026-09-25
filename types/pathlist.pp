# Auditd::EntryList for absolute paths.
type Auditd::PathList = Variant[
  Array[Stdlib::Absolutepath],
  Hash[Stdlib::Absolutepath, Struct[{ Optional['ensure'] => Enum['present', 'absent'] }]],
]
