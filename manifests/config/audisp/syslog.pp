# @summary Utilizes rsyslog to send all audit records to syslog.
#
# This capability is most useful for forwarding audit records to
# remote servers as syslog messages, since these records are already
# persisted locally in audit logs.  For most sites, however, using
# this capability for all audit records can quickly overwhelm host
# and/or network resources, especially if the messages are forwarded
# to multiple remote syslog servers or (inadvertently) persisted
# locally. Site-specific, rsyslog actions to implement filtering will
# likely be required to reduce this message traffic.
#
# If you are using simp_rsyslog, it, by default, sets up a
# rsyslog rule to drop the audispd messages from being written locally
# to prevent duplication of logging audit events on the local system.
# See simp_rsyslog::local for more information.
#
# It is also recommend you ensure any forwarded, audit messages are
# encrypted using the stunnel module, due to the nature of the
# information carried by these messages.
#
# @param rsyslog
#     (deprecated)
#     If set, enable the SIMP `rsyslog` module and set up the appropriate rules
#     for the `auditd` services.
#
# @param drop_audit_logs
#     (deprecated)
#     When set to false, auditd records will be forwarded to remote
#     servers and/or written to local syslog files, as directed by the
#     site rsyslog configuration.
#     This setting is not needed any more.  If you want to
#     disable/enable sending audit records to syslog, set
#     the 'enable' parameter in this module to false/true as appropriate.
#     It is left here for backwards compatability but will not
#     be in the next major release.
#
# @param enable
#     Enable or disable sending audit mesages to syslog.
#
# @param priority
#     The syslog priority for all audit record messages.
#     This value is used in the /etc/audisp/plugins.d/syslog.conf file.
#
# @param facility
#     The syslog facility for all audit record messages. This value is
#     used in the /etc/audisp/plugins.d/syslog.conf file.  For the older
#     auditd versions used by CentOS6 and CentOS7, must be an empty string,
#     LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5,
#     LOG_LOCAL6, or LOG_LOCAL7. An empty string results in LOG_USER and
#     is the ONLY mechanism to specify that facility. No other facilities
#     are allowed.
#
# @param syslog_path
#     The path to the syslog plugin executable.
#
#     Unset, `/sbin/audisp-syslog` on auditd >= 3.0 and the audispd builtin
#     `builtin_syslog` below it.
#
# @param type
#    The type of auditd plugin.
#
#    Unset, `always` on auditd >= 3.0 and `builtin` below it.
#
# @param pkg_name
#     The name of the plugin package to install.  Only needed for
#     auditd version 3 and later.
#
#     `audispd-plugins` from the module data. Set to `~` in Hiera to leave the
#     package unmanaged.
#
# @param package_ensure
#     The default ensure parmeter for packages.
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::audisp::syslog (
  Boolean                         $enable          = true,
  Boolean                         $drop_audit_logs = true, #deprecated see @param
  Auditd::LogPriority             $priority        = 'LOG_INFO',
  Auditd::LogFacility             $facility        = 'LOG_LOCAL5',
  Optional[String[1]]             $pkg_name        = undef, # data in module
  Optional[String[1]]             $syslog_path     = undef,
  Optional[String[1]]             $type            = undef,
  Boolean                         $rsyslog         = simplib::lookup('simp_options::syslog', { 'default_value' => false }), #deprecated see @param
  String                          $package_ensure  = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
) {
  # See auditd::config::logging for why a missing auditd_version means 3.0.
  if versioncmp(pick($facts['auditd_version'], '3.0'), '3.0') >= 0 and $enable and $pkg_name {
    package { $pkg_name :
      ensure => $package_ensure,
    }
  }

  # auditd 2 (EL7, unsupported since 9.0.0) ran the syslog plugin inside
  # audispd, from /etc/audisp. The defaults follow the detected version so a
  # host still on it keeps working; this path goes away in 12.0.0. The third
  # argument keeps deprecation() a warning under 'strict => error'.
  $_auditd2 = versioncmp($facts['auditd_version'], '3.0') < 0
  if $_auditd2 {
    deprecation('auditd::auditd2',
    'auditd < 3.0 is not a supported platform; its plugin layout will no longer be selected in 12.0.0',
    false)
  }

  # auditd::plugin_dir is unset unless a site moves the directory; fall back to
  # the path the package ships and auditd compiles in.
  $_plugin_dir = pick($auditd::plugin_dir, $_auditd2 ? {
    true    => '/etc/audisp/plugins.d',
    default => '/etc/audit/plugins.d',
  })
  $_syslog_path = pick($syslog_path, $_auditd2 ? {
    true    => 'builtin_syslog',
    default => '/sbin/audisp-syslog',
  })
  $_type = pick($type, $_auditd2 ? {
    true    => 'builtin',
    default => 'always',
  })

  file { "${_plugin_dir}/syslog.conf":
    mode    => $auditd::config::config_file_mode,
    owner   => 'root',
    content => epp("${module_name}/plugins/syslog_conf", {
      enable => $enable,
      path   => $_syslog_path,
      type   => $_type,
      args   => "${priority} ${facility}"
    }),
    require => Package[$auditd::package_name],
  }
  #
  #  The below section is here for backwards compatability. It will be removed
  #  in the next major release of this module.
  #  To disable logging audit events to syslog you should set
  #  auditd::syslog to true (to enable management of the syslog plugin).
  #  auditd::config::audisp::syslog::enable to false (to make sure the plugin is not
  #     active.)
  #  auditd::config::audisp::syslog::rsyslog to false ( so it does not install
  #     unnecessary rsyslog rules.)
  #
  if $rsyslog {
    simplib::assert_optional_dependency($module_name, 'simp/rsyslog')

    include 'rsyslog'

    if $drop_audit_logs {
      # This will prevent audit records from being forwarded to remote
      # servers and/or written to local syslog files, but you still have
      # access to the records in the local audit log files.
      rsyslog::rule::drop { 'audispd':
        rule => '$programname == \'audispd\'',
      }
    }
  }
  # End of deprecated section.
}
