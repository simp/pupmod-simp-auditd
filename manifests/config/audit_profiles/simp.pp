# == Class auditd::config::audit_profiles::simp
#
# A set of audit rules that are configured to meet the general goals of SIMP
#
# == Parameters
#
# Any variable that is not described here can be found in auditd.conf(5) and
# auditctl(8).
#
# [*immutable*]
#   Whether or not to make the configuration immutable. Be aware that, should
#   you choose to make the configuration immutable, you will not be able to
#   change your audit rules without a reboot.
#   *Default*: 'false'
#
# [*root_audit_level*]
#   What level of auditing should be used for su-root activity. Be aware that
#   setting this to anything besides 'basic' may overwhelm your system and/or
#   log server.
#   Options can be, 'basic', 'aggressive', 'insane'
#    - Basic: Safe, should not follow program execution outside of the base app
#    - Aggressive: Adds execve
#    - Insane: Adds fork, vfork, write, chown, creat, link, mkdir, rmdir
#   *Default*: 'basic'
#
# [*uid_min*]
#   Type: Integer
#   Default: $::uid_min
#     The minimum UID for human users on the system. Any logs generated by
#     users below this number will be ignored unless set to absolute first when
#     using auditd::add_rule.
#
class auditd::config::audit_profiles::simp (
  $log_file = $::auditd::log_file,
  # CCE-27522-2
  $num_logs = '5',
  $ignore_failures = $::auditd::ignore_failures,
  $buffer_size = $::auditd::buffer_size,
  $failure_mode = $::auditd::failure_mode,
  $rate = $::auditd::rate,
  $immutable = $::auditd::immutable,
  $root_audit_level = $::auditd::root_audit_level,
  $uid_min = $::auditd::uid_min,
) inherits ::auditd {
  # Move validation here from init.pp when the module is refactored

  $_profile_template_path = "${module_name}/rule_profiles/simp"

  auditd::add_rules { 'init.d_auditd':
    content => "-w /etc/rc.d/init.d/auditd -p wa -k auditd
                -w $log_file -p wa -k audit-logs"
  }

  auditd::add_rules { 'rotated_audit_logs':
    content => template("${_profile_template_path}/rotated_audit_logs.erb")
  }

  file { '/etc/audit/rules.d/00_head.rules':
    content => template("${_profile_template_path}/head.erb")
  }

  file { '/etc/audit/rules.d/05_default_drop.rules':
    content => template("${_profile_template_path}/default_drop.erb")
  }

  file { '/etc/audit/rules.d/50_base.rules':
    content => template("${_profile_template_path}/base.erb")
  }

  file { '/etc/audit/rules.d/99_tail.rules':
    content => template("${_profile_template_path}/tail.erb")
  }
}
