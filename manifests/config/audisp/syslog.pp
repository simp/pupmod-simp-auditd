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
#   The priority of the messages you want forwarded
#   This value is used in the 
#   audisp/plugins.d/syslog.conf file
#   default: LOG_INFO
#
# [*facility*] 
#   The log file facility you want used to forwarded the messages to.
#   This value is used in the 
#   audisp/plugins.d/syslog.conf file
#   default: "" 
#     the version of audit used does not recognize LOG_USER but
#     but sets facility to LOG_USER if the entry is "".
#
class auditd::config::audisp::syslog (
  $priority = "LOG_INFO",
  $facility  = "LOG_USER",
  $log_servers = hiera('log_servers',[])
) {
  validate_array($log_servers)
  validate_array_member($priority, ['LOG_INFO', 'LOG_DEBUG', 'LOG_NOTICE', 'LOG_WARNING', 'LOG_ERR', 'LOG_CRIT', 'LOG_ALERT', 'LOG_EMERG'])
  validate_array_member($facility, ['LOG_AUTH', 'LOG_AUTHPRIV', 'LOG_CRON', 'LOG_DAEMON', 'LOG_KERN', 'LOG_LP', 'LOG_MAIL', 'LOG_NEWS', 'LOG_SYSLOG', '', 'LOG_UUCP', 'LOG_LOCAL0', 'LOG_LOCAL1','LOG_LOCAL2','LOG_LOCAL3','LOG_LOCAL4','LOG_LOCAL5','LOG_LOCAL6','LOG_LOCAL7', ])

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
