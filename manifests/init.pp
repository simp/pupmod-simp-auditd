# Configure the audit daemon for use with a specified audit profile
#
# Any variable that is not described here can be found in auditd.conf(5) and
# auditctl(8).
#
# @see auditd.conf(5)
# @see auditctl(8)
#
# @param lname
#   An alias for the ``name`` variable in the configuration file. This is used
#   since ``$name`` is a reserved keyword in Puppet.
#
# @param immutable
#   Whether or not to make the configuration immutable when using built-in
#   audit profiles.  Be aware that, should you choose to make the
#   configuration immutable, you will not be able to change your audit
#   rules without a reboot.
#
# @param root_audit_level
#   What level of auditing should be used for su-root activity in built-in
#   audit profiles that provide su-root rules. Be aware that setting this to
#   anything besides 'basic' may overwhelm your system and/or log server.
#   Options can be, 'basic', 'aggressive', 'insane'.  For the 'simp' audit
#   profile, these options are as follows:
#    - Basic: Safe syscall rules, should not follow program execution outside
#      of the base app
#    - Aggressive: Adds syscall rules for execve, rmdir and variants of rename
#      and unlink
#    - Insane: Adds syscall rules for write, creat and variants of chown,
#      fork, link and mkdir
#
# @param uid_min
#   The minimum UID for human users on the system. For built-in audit profiles
#   when `$ignore_system_services` is true, any audit events generated
#   by users below this number will be ignored, unless a corresponding rule
#   is inserted *before* the UID-limiting rule in the rules list.  When using
#   `auditd::rule`, you can create such a rule by setting the `absolute`
#   parameter to be 'first'.
#
# @param at_boot
#   If true, modify the Grub settings to enable auditing at boot time.
#   Meets CCE-26785-6
#
# @param syslog
#   If true, set up audispd to send logs to syslog.
#   Meets CCE-26933-2
#
# @param default_audit_profile
#   Deprecated by `$default_audit_profiles`
#
# @param default_audit_profiles
#   The built-in audit profile(s) to use to provide global audit rule
#   configuration (error handling, buffer size, etc.) and a base set
#   of audit rules.
#   - When more than one profile is specified, the profile rules are
#     effectively concatenated in the order the profiles are listed.
#   - To add rules to the base set, use `auditd::rule`.
#   - To manage the audit rules, yourself, set this parameter to `[]`.
#   - @see `auditd::config::audit_profiles` for more details about this
#     configuration.
#
# @param service_name
#   The name of the auditd service.
#
# @param package_name
#   The name of the auditd package.
#
# @param package_ensure
#
# @param enable
#   If true, enable auditing.
#
# @param log_file
# @param log_format
# @param log_group
# @param priority_boost
# @param flush
# @param freq
# @param num_logs
# @param disp_qos
# @param dispatcher
# @param name_format
# @param max_log_file
# @param max_log_file_action
# @param space_left
# @param space_left_action
# @param action_mail_acct
# @param admin_space_left
# @param admin_space_left_action
# @param disk_full_action
# @param disk_error_action
#
# @param ignore_errors
#   Whether to set the `auditctl` '-i' option
#
# @param ignore_failures
#   Whether to set the `auditctl` '-c' option
#
# @param buffer_size
#   Value of the `auditctl` '-b' option
#
# @param failure_mode
#   Value of the `auditctl` '-f' option
#
# @param rate
#   Value of the `auditctl` '-r' option
#
# @param ignore_anonymous
#   For built-in audit profiles, whether to drop anonymous and daemon
#   events, i.e., events for which ``auid`` is '-1' (aka '4294967295').
#   Audit records from these events are prolific but not useful.
#
# @param ignore_system_services
#   For built-in audit profiles, whether to ignore system service events,
#   i.e., events for which the ``auid`` is set but is less than the
#   minimum UID for human users on the system.  In most security guides,
#   this filter is attached to every system call rule.  So, by implementing
#   the filter in an upfront drop rule, this feature provides optimization
#   of that filtering.
#
# @param ignore_crond
#   For built-in audit profiles, whether to drop events related to cron
#   jobs. `cron` creates a lot of audit events that are not usually useful.
#
class auditd (
  String                                  $lname                   = $facts['fqdn'],
  Boolean                                 $immutable               = false,
  Auditd::RootAuditLevel                  $root_audit_level        = 'basic',
  Integer[0]                              $uid_min                 = to_integer($facts['uid_min']),
  Boolean                                 $at_boot                 = true, # CCE-26785-6
  Boolean                                 $syslog                  = simplib::lookup('simp_options::syslog', {'default_value' => false }),  # CCE-26933-2
  Optional[Variant[Enum['simp'],Boolean]] $default_audit_profile   = undef,
  Array[Auditd::AuditProfile]             $default_audit_profiles  = [ 'simp' ],
  String                                  $service_name            = 'auditd',
  String                                  $package_name            = 'audit',
  String                                  $package_ensure          = 'latest',
  Boolean                                 $enable                  = true,
  Stdlib::Absolutepath                    $log_file                = '/var/log/audit/audit.log',
  Enum['RAW','NOLOG']                     $log_format              = 'RAW',
  String                                  $log_group               = 'root',
  Integer[0]                              $priority_boost          = 3,
  Auditd::Flush                           $flush                   = 'INCREMENTAL',
  Integer[0]                              $freq                    = 20,
  Integer[0]                              $num_logs                = 5, # CCE-27522-2
  Enum['lossy','lossless']                $disp_qos                = 'lossy',
  Stdlib::Absolutepath                    $dispatcher              = '/sbin/audispd',
  Auditd::NameFormat                      $name_format             = 'USER',
  Integer[0]                              $max_log_file            = 24, # CCE-27550-3
  Auditd::MaxLogFileAction                $max_log_file_action     = 'ROTATE', # CCE-27237-7
  Integer[0]                              $space_left              = 75,
  Auditd::SpaceLeftAction                 $space_left_action       = 'SYSLOG', # CCE-27238-5 : No guarantee of e-mail server so sending to syslog.
  String                                  $action_mail_acct        = 'root', # CCE-27241-9
  Integer[0]                              $admin_space_left        = 50,
  Auditd::SpaceLeftAction                 $admin_space_left_action = 'SUSPEND', # CCE-27239-3 : No guarantee of e-mail server so sending to syslog.
  Auditd::DiskFullAction                  $disk_full_action        = 'SUSPEND',
  Auditd::DiskErrorAction                 $disk_error_action       = 'SUSPEND',
  Boolean                                 $ignore_errors           = true,
  Boolean                                 $ignore_failures         = true,
  Integer[0]                              $buffer_size             = 16384,
  Integer[0]                              $failure_mode            = 1,
  Integer[0]                              $rate                    = 0,
  Boolean                                 $ignore_anonymous        = true,
  Boolean                                 $ignore_system_services  = true,
  Boolean                                 $ignore_crond            = true,
) {

  simplib::assert_metadata($module_name)

  if $enable {

    # This is done here so that the kernel option can be properly removed if
    # auditing is to be disabled on the system.
    if $at_boot {
      $_grub_enable = true
    }
    else {
      $_grub_enable = false
    }

    include 'auditd::install'
    include 'auditd::config'
    include 'auditd::service'

    Class['auditd::install']
    -> Class['auditd::config']
    ~> Class['auditd::service']
    -> Class['auditd']

    Class['auditd::install'] -> Class['::auditd::config::grub']

    if $syslog {
      include 'auditd::config::logging'

      Class['auditd::config::logging']
      ~> Class['auditd::service']
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
}
