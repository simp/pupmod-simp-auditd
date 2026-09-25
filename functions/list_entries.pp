# @summary Normalize a list parameter to a Hash of entry to `ensure`
#
# An Array lists entries to write. A Hash names each entry with an optional
# `ensure`, so `ensure => absent` can remove one.
#
# @param list
#   The list parameter, as an Array or a Hash.
#
# @return [Hash[String[1], Enum['present', 'absent']]]
#
function auditd::list_entries (
  Variant[Array[String[1]], Hash[String[1], Struct[{ Optional['ensure'] => Enum['present', 'absent'] }]]] $list
) >> Hash[String[1], Enum['present', 'absent']] {
  $list ? {
    Array   => $list.reduce({}) |$memo, $entry| { $memo + { $entry => 'present' } },
    default => $list.reduce({}) |$memo, $entry| { $memo + { $entry[0] => pick($entry[1]['ensure'], 'present') } },
  }
}
