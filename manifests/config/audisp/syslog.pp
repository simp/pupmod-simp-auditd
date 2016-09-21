# == Class auditd::config::audisp::syslog
#
# This class utilizes rsyslog to send all audit records to syslog.
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
# [*priority*]
#   Type:  String
#   Default:  LOG_INFO
#     The syslog priority for all audit record messages.
#     This value is used in the /etc/audisp/plugins.d/syslog.conf file.
#
# [*facility*]
#   Type:  String
#   Default:  ''
#     The syslog facility for all audit record messages. This value is
#     used in the /etc/audisp/plugins.d/syslog.conf file.  For the older
#     auditd versions used by CentOS6 and CentOS7, must be an empty string,
#     LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5,
#     LOG_LOCAL6, or LOG_LOCAL7. An empty string results in LOG_USER and
#     is the ONLY mechanism to specify that facility. No other facilities
#     are allowed.
#
class auditd::config::audisp::syslog (
  $log_servers = hiera('log_servers',[]),
  $priority = "LOG_INFO",
  $facility = ""
) {
  validate_array($log_servers)
  validate_array_member($priority, ['LOG_DEBUG', 'LOG_INFO',
    'LOG_NOTICE', 'LOG_WARNING', 'LOG_ERR', 'LOG_CRIT', 'LOG_ALERT',
    'LOG_EMERG'])

  validate_array_member($facility, ['', 'LOG_LOCAL0', 'LOG_LOCAL1',
    'LOG_LOCAL2', 'LOG_LOCAL3', 'LOG_LOCAL4', 'LOG_LOCAL5', 'LOG_LOCAL6',
    'LOG_LOCAL7'])

  if !empty($log_servers) {
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
args = ${priority} ${facility}
format = string
"
  }
}
