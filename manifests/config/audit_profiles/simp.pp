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
  # These are booleans to toggle sections of audit rules
  $ignore_errors = true,
  $ignore_anonymous = true,
  $ignore_system_services = true,
  $audit_unsuccessful_file_operations = true,
  $audit_unsuccessful_file_operations_tag = 'access',
  $audit_permissions = true,
  $audit_permissions_tag = 'perm_mod',
  $audit_su_root_activity = true,
  $audit_su_root_activity_tag = 'su-root-activity',
  $audit_suid_sgid = true,
  $audit_suid_sgid_tag = 'suid-root-exec',
  $audit_kernel_modules = true,
  $audit_kernel_modules_tag = 'modules',
  $audit_time = true,
  $audit_time_tag = 'audit_time_rules',
  $audit_locale = true,
  $audit_locale_tag = 'audit_network_modifications',
  $audit_mount = true,
  $audit_mount_tag = 'mount',
  $audit_umask = false,
  $audit_umask_tag = 'umask',
  $audit_local_account = true,
  $audit_local_account_tag = 'audit_account_changes',
  $audit_selinux_policy = true,
  $audit_selinux_policy_tag = 'MAC-policy',
  $audit_login_files = true,
  $audit_login_files_tag = 'logins',
  $audit_session_files = true,
  $audit_session_files_tag = 'session',
  $audit_sudoers = true,
  $audit_sudoers_tag = 'CFG_sys',
  $audit_grub = true,
  $audit_grub_tag = 'CFG_grub',
  $audit_cfg_sys = true,
  $audit_cfg_sys_tag = 'CFG_sys',
  $audit_cfg_cron = true,
  $audit_cfg_cron_tag = 'CFG_cron',
  $audit_cfg_shell = true,
  $audit_cfg_shell_tag = 'CFG_shell',
  $audit_cfg_pam = true,
  $audit_cfg_pam_tag = 'CFG_pam',
  $audit_cfg_security = true,
  $audit_cfg_security_tag = 'CFG_security',
  $audit_cfg_services = true,
  $audit_cfg_services_tag = 'CFG_services',
  $audit_cfg_xinetd = true,
  $audit_cfg_xinetd_tag = 'CFG_xinetd',
  $audit_yum = true,
  $audit_yum_tag = 'yum-config',
  $audit_ptrace = true,
  $audit_ptrace_tag = 'paranoid',
  $audit_personality = true,
  $audit_personality_tag = 'paranoid',
) inherits ::auditd {

  compliance_map()
  # Move validation here from init.pp when the module is refactored

  validate_bool($ignore_errors)
  validate_bool($ignore_anonymous)
  validate_bool($ignore_system_services)
  validate_bool($audit_unsuccessful_file_operations)
  validate_string($audit_unsuccessful_file_operations_tag)
  validate_bool($audit_permissions)
  validate_string($audit_permissions_tag)
  validate_bool($audit_su_root_activity)
  validate_string($audit_su_root_activity_tag)
  validate_bool($audit_suid_sgid)
  validate_string($audit_suid_sgid_tag)
  validate_bool($audit_kernel_modules)
  validate_string($audit_kernel_modules_tag)
  validate_bool($audit_time)
  validate_string($audit_time_tag)
  validate_bool($audit_locale)
  validate_string($audit_locale_tag)
  validate_bool($audit_mount)
  validate_string($audit_mount_tag)
  validate_bool($audit_umask)
  validate_string($audit_umask_tag)
  validate_bool($audit_local_account)
  validate_string($audit_local_account_tag)
  validate_bool($audit_selinux_policy)
  validate_string($audit_selinux_policy_tag)
  validate_bool($audit_login_files)
  validate_string($audit_login_files_tag)
  validate_bool($audit_session_files)
  validate_string($audit_session_files_tag)
  validate_bool($audit_sudoers)
  validate_string($audit_sudoers_tag)
  validate_bool($audit_grub)
  validate_string($audit_grub_tag)
  validate_bool($audit_cfg_sys)
  validate_string($audit_cfg_sys_tag)
  validate_bool($audit_cfg_cron)
  validate_string($audit_cfg_cron_tag)
  validate_bool($audit_cfg_shell)
  validate_string($audit_cfg_shell_tag)
  validate_bool($audit_cfg_pam)
  validate_string($audit_cfg_pam_tag)
  validate_bool($audit_cfg_security)
  validate_string($audit_cfg_security_tag)
  validate_bool($audit_cfg_services)
  validate_string($audit_cfg_services_tag)
  validate_bool($audit_cfg_xinetd)
  validate_string($audit_cfg_xinetd_tag)
  validate_bool($audit_yum)
  validate_string($audit_yum_tag)
  validate_bool($audit_ptrace)
  validate_string($audit_ptrace_tag)
  validate_bool($audit_personality)
  validate_string($audit_personality_tag)

  $_profile_template_path = "${module_name}/rule_profiles/simp"

  auditd::add_rules { 'init.d_auditd':
    content => "-w /etc/rc.d/init.d/auditd -p wa -k auditd
                -w ${log_file} -p wa -k audit-logs"
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