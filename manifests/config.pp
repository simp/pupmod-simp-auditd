# This class is called from auditd for service config.
#
# Any variable that is not described here can be found in auditd.conf(5) and
# auditctl(8).
#
# @param lname
#     An alias for the 'name' variable in the configuration file. This is used
#     since $name is a reserved keyword in Puppet.
#
# @param default_audit_profile
#     Set the default audit rules of the system to the named profile.
#     Suported Values: 'simp', false
#
#     If false, no built-in audit profile is used.
class auditd::config (
  Stdlib::Absolutepath          $log_file                = $::auditd::log_file,
  Enum['RAW','NOLOG']           $log_format              = $::auditd::log_format,
  String                        $log_group               = $::auditd::log_group,
  Stdlib::Compat::Integer       $priority_boost          = $::auditd::priority_boost,
  Auditd::Flush                 $flush                   = $::auditd::flush,
  Stdlib::Compat::Integer       $freq                    = $::auditd::freq,
  Stdlib::Compat::Integer       $num_logs                = $::auditd::num_logs, # CCE-27522-2
  Enum['lossy','lossless']      $disp_qos                = $::auditd::disp_qos,
  Stdlib::Absolutepath          $dispatcher              = $::auditd::dispatcher,
  Auditd::NameFormat            $name_format             = $::auditd::name_format,
  String                        $lname                   = $::auditd::lname,
  Stdlib::Compat::Integer       $max_log_file            = $::auditd::max_log_file, # CCE-27550-3
  Auditd::MaxLogFileAction      $max_log_file_action     = $::auditd::max_log_file_action, # CCE-27237-7
  Stdlib::Compat::Integer       $space_left              = $::auditd::space_left,
  Auditd::SpaceLeftAction       $space_left_action       = $::auditd::space_left_action, # CCE-27238-5 : No guarantee of e-mail server so sending to syslog.
  String                        $action_mail_acct        = $::auditd::action_mail_acct, # CCE-27241-9
  Stdlib::Compat::Integer       $admin_space_left        = $::auditd::admin_space_left,
  Auditd::SpaceLeftAction       $admin_space_left_action = $::auditd::admin_space_left_action, # CCE-27239-3 : No guarantee of e-mail server so sending to syslog.
  Auditd::DiskFullAction        $disk_full_action        = $::auditd::disk_full_action,
  Auditd::DiskErrorAction       $disk_error_action       = $::auditd::disk_error_action,
  Variant[Enum['simp'],Boolean] $default_audit_profile   = $::auditd::default_audit_profile
) inherits ::auditd {
  # Move validation here from init.pp when the module is refactored

  if $default_audit_profile {
    if $default_audit_profile == true {
      $_audit_profile = 'simp'
    }
    else {
      $_audit_profile = $default_audit_profile
    }
    contain "::auditd::config::audit_profiles::${_audit_profile}"
  }

  file { '/etc/audit/rules.d':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
    recurse => true,
    purge   => true
  }

  file { '/etc/audit/audit.rules':
    owner => 'root',
    group => 'root',
    mode  => '0600'
  }

  file { '/etc/audit/auditd.conf':
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => template("${module_name}/etc/audit/auditd.conf.erb")
  }

  file { '/var/log/audit':
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => 'o-rwx'
  }

  file { $log_file:
    owner => 'root',
    group => 'root',
    mode  => '0600'
  }
}
