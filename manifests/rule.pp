# This define allows you to add rules to the auditd.rules file.  These rules
# should be uniquely named.  See auditctl(8) for more information on how to
# write the content for these rules.
#
# @param name
#   A unique identifier for the audit rules.
#
# @param content
#   The content of the rules that should be added.
#
# @param first
#   Set this to 'true' if you want to prepend your custom rules.
#     Default: false
#
# @param absolute
#   Set this to 'true' if you want the added rules to be absolutely first or
#   last depending on the setting of $first.
#     Default: false
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
# @author Chris Tessmer  <chris.tessmer@onyxpoint.com>
#
define auditd::rule (
  String  $content,
  Boolean $first    = false,
  Boolean $absolute = false,
  Boolean $prepend  = false
) {
  include 'auditd'

  if $::auditd::enable {

    if $prepend {
      $rule_id = "00.${name}.rules"
    }
    else {
      if $first {
        if $absolute {
          $rule_id = "01.${name}.rules"
        }
        else {
          $rule_id = "10.${name}.rules"
        }
      }
      else {
        $rule_id = "75.${name}.rules"
      }
    }

    file { "/etc/audit/rules.d/${rule_id}":
      content => template('auditd/rule.erb'),
      notify  => Class['::auditd::service']
    }
  }
  else {
    debug("Auditd is disabled, not activating auditd::rule::${name}")
  }
}
