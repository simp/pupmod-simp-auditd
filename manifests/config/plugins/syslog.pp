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
# It is also recommend you ensure any forwarded, audit messages are
# encrypted using the stunnel module, due to the nature of the
# information carried by these messages.
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
# @param type
#    The type of auditd plugin.
#
# @param pkg_name
#     The name of the plugin package to install.  Only needed for
#     auditd version 3 and later.
#
# @param package_ensure
#     The default ensure parmeter for packages.
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::plugins::syslog (
  Boolean                         $enable          = true,
  Auditd::LogPriority             $priority        = 'LOG_INFO',
  Auditd::LogFacility             $facility        = 'LOG_LOCAL5',
  Optional[String]                $pkg_name        = undef,
  String                          $syslog_path,    # data in module
  String                          $type,           # data in module
  String                          $package_ensure  = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
) {

  if versioncmp($facts['auditd_version'], '3.0') >= 0  and $enable {
    package { $pkg_name :
      ensure => $package_ensure
    }
  }

  file { "${auditd::plugin_dir}/syslog.conf":
    mode    => '0644',
    owner   => 'root',
    content => epp("${module_name}/plugins/syslog_conf", {
      enable =>  $enable,
      path   =>  $syslog_path,
      type   =>  $type,
      args   => "${priority} ${facility}"
      })
  }

}
