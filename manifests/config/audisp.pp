# @summary Configures the audit dispatcher primarily for sending audit logs directly to syslog without intervention.
#
# All parameters are documented in audispd.conf(5) with the exception
# of $specific_name which maps to the audispd.conf 'name' variable.
#
# This module is only used for auditd versions before 3.0.  These parameters are
# set in auditd.conf for version 3.0 and later.
# @param specific_name
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::audisp (
  String                 $specific_name   = $facts['fqdn']
) {

  if  versioncmp($facts['auditd_version'], '3.0') < 0 {
    include auditd::config::audisp_service

    file { '/etc/audisp/audispd.conf':
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => "# This file managed by Puppet
q_depth         = ${auditd::q_depth}
overflow_action = ${auditd::overflow_action}
priority_boost  = ${auditd::priority_boost}
max_restarts    = ${auditd::max_restarts}
name_format     = ${auditd::name_format}
name            = ${specific_name}
"
    }
  }
}
