# This class is called from auditd::config.  It provides global audit
# rule configuration and a base set of audit rules based on the
# built-in audit profile(s).
#
# The configuration generated is contained in a set of files in
# `/etc/audit/rules.d`, which `augenrules` parses for `auditd` in
# natural sort order, to create a single `/etc/audit/auditd.rules`
# file. The generated files are as follows:
# - `00_head.rules`:  Contains `auditctl` general configuration to
#   remove existing rules when the rules are reloaded, ignore rule
#   load errors/failures, and set the buffer size, failure mode,
#   and rate limiting.
# - `05_default_drop.rules`: Contains filtering rules for efficiency
#   - Rules to drop prolific events of low-utility
#   - Rules to restrict events based on `auid` constraints that would
#     normally be applied to all rules
# - `50_*base.rules`:
#   - Nominal base rules for one or more built-in profiles.
#   - One file will exist for each desired, built-in profile.
#   - Files are named so that the ordering of profiles listed
#     in `$::auditd::default_audit_profiles` is preserved.
#   - The corresponding class for each profile is
#    `auditd::config::audit_profiles::<profile name>`.
# - `75.init.d_auditd.rules`:
#    - A watch rule for `/etc/rc.d/init.d/auditd` permissions changes
#    - A watch rule for permissions changes to the `auditd` log file
# - `75.rotated_audit_logs.rules`
#    - Watch rules for permissions changes to the rotated `auditd` log files
# - `99_tail.rules`
#   - `auditctl` immutable option, when `$::auditd::immutable` is 'true'
#
class auditd::config::audit_profiles {

  assert_private()

  $_common_template_path = "${module_name}/rule_profiles/common"

  auditd::rule { 'init.d_auditd':
    content => "-w /etc/rc.d/init.d/auditd -p wa -k auditd
                -w ${$::auditd::log_file} -p wa -k audit-logs"
  }


  $_num_logs = $::auditd::num_logs
  $_log_file = $::auditd::log_file
  auditd::rule { 'rotated_audit_logs':
    content => template("${_common_template_path}/rotated_audit_logs.erb")
  }

  if ( $::auditd::root_audit_level == 'aggressive' ) and ( $::auditd::buffer_size < 32788 ) {
    $_buffer_size = 32788
  } elsif ( $::auditd::root_audit_level == 'insane' ) and ( $::auditd::buffer_size < 65576 ) {
    $_buffer_size = 65576
  } else {
    $_buffer_size = $::auditd::buffer_size
  }

  file { '/etc/audit/rules.d/00_head.rules':
    content => epp("${_common_template_path}/head.epp")
  }

  file { '/etc/audit/rules.d/05_default_drop.rules':
    content => epp("${_common_template_path}/default_drop.epp")
  }

  file { '/etc/audit/rules.d/99_tail.rules':
    content => epp("${_common_template_path}/tail.epp")
  }

  $::auditd::default_audit_profiles.each | String $audit_profile | {
    # use contain instead of include so that config file changes can
    # notify auditd::service class
    contain "auditd::config::audit_profiles::${audit_profile}"
  }


}
