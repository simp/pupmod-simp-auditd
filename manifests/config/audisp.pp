# @summary Configures the audit dispatcher primarily for sending audit logs directly to syslog without intervention.
#
# All parameters are documented in audispd.conf(5) with the exception
# of $specific_name which maps to the audispd.conf 'name' variable.
#
# @param q_depth
# @param overflow_action
# @param priority_boost
# @param max_restarts
# @param name_format
# @param specific_name
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::audisp (
  Integer                $q_depth         = 160,
  Auditd::OverflowAction $overflow_action = 'SYSLOG',
  Integer                $priority_boost  = 4,
  Integer                $max_restarts    = 10,
  Auditd::NameFormat     $name_format     = 'USER',
  String                 $specific_name   = $facts['fqdn']
) {

  file { '/etc/audisp/audispd.conf':
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
    content => "# This file managed by Puppet
q_depth         = ${q_depth}
overflow_action = ${overflow_action}
priority_boost  = ${priority_boost}
max_restarts    = ${max_restarts}
name_format     = ${name_format}
name            = ${specific_name}
"
  }
}
