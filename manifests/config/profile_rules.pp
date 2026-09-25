# @summary Manage one toggle's rules in a profile's base rules file
#
# Each rule is edited in place with `file_line`, matched on everything before
# its key (see `auditd::rule_match`). A rule this toggle does not know about,
# including one deleted from a list parameter, is left alone; a list entry set
# to `ensure => absent` is removed.
#
# @api private
#
# @param path
#   The profile's base rules file.
#
# @param enable
#   `true` writes the rules; `false` removes them.
#
# @param key
#   The key written on each rule.
#
# @param rules
#   The rules without their keys, in file order. A `[rule, key]` pair gives a
#   rule its own key. A Hash with `rule` and `ensure` can remove one rule while
#   the toggle is `true`. Rules for `arch=b64` are skipped on anything but
#   x86_64.
#
# @param key_option
#   How the key is written: `-k <key>` or `-F key=<key>`.
#
# @param any_syscalls
#   Match any `-S` list, so a changed list replaces the rules in place.
#
# @param shared_rules
#   Rules another toggle in the same file also writes, with its own key. These
#   are matched with their key too, so the two lines leave each other alone.
#   A changed key then adds a line instead of replacing the old one.
#
define auditd::config::profile_rules (
  Stdlib::Absolutepath                                    $path,
  Boolean                                                 $enable,
  String[1]                                               $key,
  Array[Variant[
    String[1],
    Tuple[String[1], String[1]],
    Struct[{ 'rule' => String[1], Optional['ensure'] => Enum['present', 'absent'] }],
  ]]                                                      $rules,
  Enum['-k', '-F key=']                                   $key_option   = '-k',
  Boolean                                                 $any_syscalls = false,
  Array[String[1]]                                        $shared_rules = [],
) {
  assert_private()

  $_x86_64 = $facts['os']['hardware'] == 'x86_64'

  $rules.each |$entry| {
    [$_rule, $_rule_key, $_ensure] = $entry ? {
      String  => [$entry, $key, 'present'],
      Hash    => [$entry['rule'], $key, pick($entry['ensure'], 'present')],
      default => [$entry[0], $entry[1], 'present'],
    }

    unless !$_x86_64 and $_rule =~ /arch=b64/ {
      $_key = $key_option ? {
        '-k'    => "-k ${_rule_key}",
        default => "-F key=${_rule_key}",
      }

      $_match_key = ($_rule in $shared_rules) ? {
        true    => $_rule_key,
        default => undef,
      }

      $_line = ($enable and $_ensure == 'present') ? {
        true    => "${_rule} ${_key}",
        default => undef,
      }

      auditd::config::rule_line { "${title} ${_rule}":
        path  => $path,
        match => auditd::rule_match($_rule, $any_syscalls, $_match_key),
        line  => $_line,
      }
    }
  }
}
