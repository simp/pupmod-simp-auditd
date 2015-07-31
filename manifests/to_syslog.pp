# == Class auditd::to_syslog
#
# Activating this define utilizes rsyslog to send all audit records to syslog.
# This will definitely increase the volume of log messages passing out of your
# system and you should probably ensure that they are encrypted using the
# stunnel module.
#
# == Parameters
#
# [*log_server*]
#   The server to which to send the logs.
#
# [*encrypt_logs*]
#   If set to 'true', this will send the logs to
#   127.0.0.1:$encrypted_port.
#
#   This expects an stunnel type setup.
#
# [*encrypted_port*]
#   The port to which to send the logs on localhost.
#
# == Authors
#
# Trevor Vaughan <tvaughan@onyxpoint.com>
#
class auditd::to_syslog (
  $log_servers = hiera('log_servers',[])
) {
  if !empty($log_servers) {
    include '::rsyslog'

    # Note: This only happens if you are offloading your logs.
    # Otherwise, just go look at the audit files.
    rsyslog::rule::drop { 'audispd':
      rule   => 'if $programname == \'audispd\''
    }
  }

  file { '/etc/audisp/plugins.d/syslog.conf':
    content => "\
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_INFO
format = string
"
  }
  validate_array($log_servers)
}
