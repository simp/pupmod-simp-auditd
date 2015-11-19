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
  $q_depth = '160',
  $overflow_action = 'syslog',
  $priority_boost = '4',
  $max_restarts = '10',
  $name_format = 'user',
  $specific_name = $::fqdn
) {
  validate_integer($q_depth)
  validate_array_member($overflow_action,['ignore','syslog','suspend','single','halt'],'i')
  validate_integer($priority_boost)
  validate_integer($max_restarts)
  validate_array_member($name_format,['none','hostname','fqd','numeric','user'],'i')

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
