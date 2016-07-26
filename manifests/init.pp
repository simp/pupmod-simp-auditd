# == Class: auditd
#
# Configure the audit daemon for use.
#
# This module is a component of the System Integrity Management Platform, a
# a managed security compliance framework built on Puppet.
#
# This module is optimally designed for use within a larger SIMP ecosystem, but
# it can be used independently:
#
# * When included within the SIMP ecosystem,
#   security compliance settings will be managed from the Puppet server.
#
# * If used independently, all SIMP-managed security subsystems are disabled by
#   default, and must be explicitly opted into by administrators.  Please review
#   the +client_nets+ and +$enable_*+ parameters for details.
#
# == Parameters
#
# Any variable that is not described here can be found in auditd.conf(5) and
# auditctl(8).
#
# [*lname*]
#   An alias for the 'name' variable in the configuration file. This is used
#   since $name is a reserved keyword in Puppet.
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
# [*at_boot*]
#   Type: Boolean
#   Default: true
#     If true, modify the Grub settings to enable auditing at boot time.
#     Meets CCE-26785-6
#
# [*to_syslog*]
#   Type: Boolean
#   Default: true
#     If true, set up audispd to send logs to syslog.
#     Meets CCE-26933-2
#
# [*default_audit_profile*]
#   Type: String
#   Default: 'simp'
#     Set the default audit rules of the system to the named profile.
#     Supported Values: 'simp', false
#
#     If false, no built-in audit profile is used.
#
# [*service_name*]
#   The name of the auditd service.
#   Type: String
#     Default:  +$::auditd::params::service_name+
#
# [*package_name*]
#   Type: String
#   Default:  +$::auditd::params::package_name+
#     The name of the auditd package.
#
# [*enable_auditing*]
#   Type: Boolean
#   Default: +true+
#     If true, enable auditing. In this case, this will turn the auditd class
#     into a NOOP.
#
class auditd (
  $ignore_failures = true,
  $log_file = '/var/log/audit/audit.log',
  $log_format = 'RAW',
  $log_group = 'root',
  $priority_boost = '3',
  $flush = 'INCREMENTAL',
  $freq = '20',
  # CCE-27522-2
  $num_logs = '5',
  $disp_qos = 'lossy',
  $dispatcher = '/sbin/audispd',
  $name_format = 'USER',
  $lname = $::fqdn,
  # CCE-27550-3
  $max_log_file = '24',
  # CCE-27237-7
  $max_log_file_action = 'ROTATE',
  $space_left = '75',
  # CCE-27238-5 : No guarantee of e-mail server so sending to syslog.
  $space_left_action = 'SYSLOG',
  # CCE-27241-9
  $action_mail_acct = 'root',
  $admin_space_left = '50',
  # CCE-27239-3 : No guarantee of e-mail server so sending to syslog.
  $admin_space_left_action = 'SUSPEND',
  $disk_full_action = 'SUSPEND',
  $disk_error_action = 'SUSPEND',
  $buffer_size = '16384',
  $failure_mode = '2',
  $rate = '0',
  $immutable = false,
  $root_audit_level = 'basic',
  $uid_min = $::uid_min,
  # CCE-26785-6
  $at_boot = true,
  # CCE-26933-2
  $to_syslog = defined('$::enable_logging')  ? { true => $::enable_logging,  default => hiera('enable_logging',true) },
  $default_audit_profile = 'simp',
  $service_name    = $::auditd::params::service_name,
  $package_name    = $::auditd::params::package_name,
  $package_ensure  = 'latest',
  $enable_auditing = defined('$::enable_auditing') ? { true => $::enable_auditing, default => hiera('enable_auditing',true) },
  # This should be enabled during the refactor when 'to_syslog' is removed
  #$enable_logging  = defined('$::enable_logging')  ? { true => $::enable_logging,  default => hiera('enable_logging',true) }
) inherits ::auditd::params {

  validate_bool($ignore_failures)
  validate_absolute_path($log_file)
  validate_array_member($log_format,['RAW','NOLOG'],'i')
  validate_integer($priority_boost)
  validate_array_member($flush,['NONE','INCREMENTAL','DATA','SYNC'],'i')
  validate_integer($freq)
  validate_integer($num_logs)
  validate_array_member($disp_qos,['lossy','lossless'])
  validate_absolute_path($dispatcher)
  validate_array_member($name_format,['NONE','HOSTNAME','FQD','NUMERIC','USER'],'i')
  validate_integer($max_log_file)
  validate_integer($space_left)
  validate_integer($admin_space_left)
  if getvar('::auditd_version') and (versioncmp($::auditd_version,'2.4.1') >= 0) {
    validate_array_member($space_left_action, ['IGNORE','SYSLOG','ROTATE','EMAIL','EXEC','SUSPEND','SINGLE','HALT'],'i')
    validate_array_member($admin_space_left_action, ['IGNORE','SYSLOG','ROTATE','EMAIL','EXEC','SUSPEND','SINGLE','HALT'],'i')
    validate_array_member($disk_full_action, ['IGNORE','SYSLOG','ROTATE','EXEC','SUSPEND','SINGLE','HALT'],'i')
  } else {
    validate_array_member($space_left_action, ['IGNORE','SYSLOG','EMAIL','EXEC','SUSPEND','SINGLE','HALT'],'i')
    validate_array_member($admin_space_left_action, ['IGNORE','SYSLOG','EMAIL','EXEC','SUSPEND','SINGLE','HALT'],'i')
    validate_array_member($disk_full_action, ['IGNORE','SYSLOG','EXEC','SUSPEND','SINGLE','HALT'],'i')
  }
  validate_array_member($disk_error_action,['IGNORE','SYSLOG','EXEC','SUSPEND','SINGLE','HALT'],'i')
  validate_integer($buffer_size)
  validate_integer($failure_mode)
  validate_integer($rate)
  validate_bool_simp($immutable)
  validate_array_member($root_audit_level,['basic','aggressive','insane'])
  validate_integer($uid_min)
  validate_bool($at_boot)
  validate_bool($to_syslog)
  validate_array_member($default_audit_profile,['simp',false,true])
  validate_string($service_name)
  validate_string($package_name)
  validate_bool($enable_auditing)
  #validate_bool($enable_logging)

  compliance_map()

  # This is done here so that theh kernel option can be properly removed if
  # auditing is to be disabled on the system.
  if $enable_auditing {
    if $at_boot {
      $_grub_enable = true
    }
    else {
      $_grub_enable = false
    }
  }
  else {
    $_grub_enable = false
  }
  # This is done deliberately so that you cannot conflict a direct call to
  # auditd::config::grub with an include somewhere else. auditd::config::grub
  # would normally be a private class but may be used independently if
  # necessary.
  class { '::auditd::config::grub': enable => $_grub_enable }

  if $enable_auditing {
    include '::auditd::install'
    include '::auditd::config'
    include '::auditd::service'

    Class['::auditd::install'] ->
    Class['::auditd::config']  ~>
    Class['::auditd::service'] ->
    Class['::auditd']

    Class['::auditd::install'] -> Class['::auditd::config::grub']

    # Change to $enable_logging after the refactor
    if $to_syslog {
      include '::auditd::config::logging'

      Class['::auditd::config::logging'] ~>
      Class['::auditd::service']
    }
  }
}
