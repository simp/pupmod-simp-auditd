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
#     for the `auditd` services. No longer read from `simp_options::syslog`;
#     `simp:defaults` sets `true`.
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
#     `audispd-plugins` from the module data. The package is always managed
#     on auditd 3 and later when the plugin is enabled.
#
# @param package_ensure
#     The `ensure` for the plugin package. No longer read from
#     `simp_options::package_ensure`.
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::audisp::syslog (
  Boolean                         $enable          = true,
  Boolean                         $drop_audit_logs = true, #deprecated see @param
  Auditd::LogPriority             $priority        = 'LOG_INFO',
  Auditd::LogFacility             $facility        = 'LOG_LOCAL5',
  String[1]                       $pkg_name,       # data in module
  Optional[String[1]]             $syslog_path     = undef,
  Optional[String[1]]             $type            = undef,
  Boolean                         $rsyslog         = false, #deprecated see @param
  String                          $package_ensure  = 'installed',
) {
  # See auditd::config::logging for why a missing auditd_version means 3.0.
  if versioncmp(pick($facts['auditd_version'], '3.0'), '3.0') >= 0 and $enable {
    package { $pkg_name :
      ensure => $package_ensure,
    }

    # The edits below rely on the file the plugin package ships. Written
    # first, the package would leave its own copy as syslog.conf.rpmnew.
    $_syslog_conf_require = [Package[$auditd::package_name], Package[$pkg_name]]
  }
  else {
    $_syslog_conf_require = [Package[$auditd::package_name]]
  }

  # auditd 2 (EL7, unsupported since 9.0.0) ran the syslog plugin inside
  # audispd, from /etc/audisp. The defaults follow the detected version so a
  # host still on it keeps working; this path goes away in 12.0.0. The third
  # argument keeps deprecation() a warning under 'strict => error'.
  $_auditd2 = versioncmp(pick($facts['auditd_version'], '3.0'), '3.0') < 0
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

  $_syslog_conf = "${_plugin_dir}/syslog.conf"

  # Two cases cannot rely on the packaged file, and get every key: auditd 2,
  # whose audispd needs the builtin plugin, and a relocated plugin_dir, where
  # the package never put a syslog.conf.
  $_full = $_auditd2 or $auditd::plugin_dir =~ NotUndef
  $_syslog_conf_ensure = $_full ? { true => 'file', default => undef }

  # syslog.conf is otherwise the audispd-plugins package's own
  # %config(noreplace) file. This resource only enforces ownership and mode
  # there; with no ensure it does not create the file. Where there is no
  # packaged file ($_full), it creates it, so the ini_settings below never
  # create it with the umask mode.
  file { $_syslog_conf:
    ensure  => $_syslog_conf_ensure,
    owner   => 'root',
    mode    => $auditd::config::config_file_mode,
    require => $_syslog_conf_require,
  }

  # Only the keys this module has an opinion about are edited. The packaged
  # file already carries direction = out, path = /sbin/audisp-syslog,
  # type = always and format = string, so on auditd 3 and later those are left
  # alone unless a site sets path or type.
  #
  # Disabled, only active is written, so a plugin that was on is switched off
  # without filling in a file for a plugin nothing will start.
  if $enable {
    $_syslog_conf_settings = {
      'active'    => 'yes',
      'direction' => $_full ? { true => 'out', default => undef },
      'path'      => ($_full or $syslog_path =~ NotUndef) ? { true => $_syslog_path, default => undef },
      'type'      => ($_full or $type =~ NotUndef) ? { true => $_type, default => undef },
      'args'      => "${priority} ${facility}",
      'format'    => $_full ? { true => 'string', default => undef },
    }.filter |$setting, $value| { $value =~ NotUndef }
  }
  else {
    $_syslog_conf_settings = { 'active' => 'no' }
  }

  $_syslog_conf_settings.each |$setting, $value| {
    ini_setting { "syslog.conf ${setting}":
      path              => $_syslog_conf,
      section           => '',
      key_val_separator => ' = ',
      setting           => $setting,
      value             => $value,
      require           => File[$_syslog_conf],
    }
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
