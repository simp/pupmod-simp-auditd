# == Define: auditd::add_rules
#
# This define allows you to add rules to the auditd.rules file.  These rules
# should be uniquely named.  See auditctl(8) for more information on how to
# write the content for these rules.
#
# == Parameters
#
# [*name*]
#   A unique identifier for the audit rules.
#
# [*content*]
#   The content of the rules that should be added.
#
# [*first*]
#   Boolean:
#   Set this to 'true' if you want to prepend your custom rules.
#     Default: false
#
# [*absolute*]
#   Boolean:
#   Set this to 'true' if you want the added rules to be absolutely first or
#   last depending on the setting of $first.
#     Default: false
#
# == Authors
#
# Trevor Vaughan <tvaughan@onyxpoint.com>
# Chris Tessmer  <chris.tessmer@onyxpoint.com>
#
define auditd::add_rules (
  $content,
  $first    = false,
  $absolute = false,
  $prepend  = false
) {
  validate_string($content)
  validate_bool($first)
  validate_bool($absolute)
  validate_bool($prepend)

  if $prepend {
    $suffix = 'pre'
  }
  else {
    $suffix = 'post'
  }

  if $first {
    if $absolute {
      $fragname = "01.${name}.rules.${suffix}"
    }
    else {
      $fragname = "10.${name}.rules.${suffix}"
    }
  }
  else {
    $fragname = "75.${name}.rules.${suffix}"
  }

  if $::operatingsystem in ['RedHat','CentOS'] and $::operatingsystemmajrelease < '7' {
    concat_fragment { "auditd+${fragname}":
      content => template('auditd/rule.erb')
    }
  }
  else {
    file { "/etc/audit/rules.d/${fragname}":
      content => template('auditd/rule.erb'),
      notify  => Service['auditd']
    }
  }
}
