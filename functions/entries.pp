# @summary Combine a list's `*_entries` Hash with its deprecated Array parameter
#
# Returns each entry mapped to its `ensure`. Array entries are applied last,
# as `present`, so a site's old data still wins. An entry written as
# `--entry` (a Hiera knockout that reached the class) becomes `absent`.
#
# @param entries
#   The Hash of entry to its options.
#
# @param legacy
#   The deprecated Array parameter.
#
# @return [Hash[String[1], Enum['present', 'absent']]]
#
function auditd::entries (
  Hash[String[1], Auditd::EntryOptions] $entries,
  Array[String[1]]                      $legacy = [],
) >> Hash[String[1], Enum['present', 'absent']] {
  $_entries = $entries.reduce({}) |$memo, $entry| {
    $memo + { $entry[0] => pick($entry[1]['ensure'], 'present') }
  }

  $_entries + $legacy.reduce({}) |$memo, $entry| {
    $memo + ($entry =~ /^--/ ? {
      true    => { $entry.regsubst(/^--/, '') => 'absent' },
      default => { $entry => 'present' },
    })
  }
}
