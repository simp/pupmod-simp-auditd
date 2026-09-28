# @summary Combine a list's `*_ensure` Hash with its deprecated Array parameter
#
# Array entries are applied last, as `present`, so a site's old data still
# wins. An entry written as `--entry` (a Hiera knockout that reached the
# class) becomes `absent`.
#
# @param entries
#   The Hash of entry to `present` or `absent`.
#
# @param legacy
#   The deprecated Array parameter.
#
# @return [Hash[String[1], Enum['present', 'absent']]]
#
function auditd::entries (
  Hash[String[1], Enum['present', 'absent']] $entries,
  Array[String[1]]                           $legacy = [],
) >> Hash[String[1], Enum['present', 'absent']] {
  $entries + $legacy.reduce({}) |$memo, $entry| {
    $memo + ($entry =~ /^--/ ? {
      true    => { $entry.regsubst(/^--/, '') => 'absent' },
      default => { $entry => 'present' },
    })
  }
}
