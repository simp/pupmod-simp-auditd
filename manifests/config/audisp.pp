# == Class: auditd::config::audisp
#
# This class configures the audit dispatcher primarily for sending audit logs
# directly to syslog without intervention.
#
# == Parameters
#
# All parameters are documented in audispd.conf(5) with the exception
# of $specific_name which maps to the audispd.conf 'name' variable.
#
# == Authors
#
# Trevor Vaughan <tvaugan@onyxpoint.com>
#
class auditd::config::audisp (
  Stdlib::Compat::Integer $q_depth = '160',
  Pattern[/(?i:ignore|syslog|suspend|single|halt)/] $overflow_action = 'syslog',
  Stdlib::Compat::Integer $priority_boost = '4',
  Stdlib::Compat::Integer $max_restarts = '10',
  Pattern[/(?i:none|hostname|fqdn|numeric|user)/] $name_format = 'user',
  String $specific_name = $::fqdn
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
