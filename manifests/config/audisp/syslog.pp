# This class utilizes rsyslog to send all audit records to syslog.
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
# As a precaution, to prevent the above overload scenario, this class,
# by default, inserts a rsyslog action to drop these messages, prior to
# forwarding to remote syslog servers or writing to local syslog files.
# You can disable this drop behavior via configuration, but are strongly
# advised to apply appropriate syslog message filtering before doing so.
# We also recommend you ensure any forwarded, audit messages are
# encrypted using the stunnel module, due to the nature of the
# information carried by these messages.
#
# @param drop_audit_logs
#     When set to false, auditd records will be forwarded to remote
#     servers and/or written to local syslog files, as directed by the
#     site rsyslog configuration.
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
class auditd::config::audisp::syslog (
  Boolean             $drop_audit_logs = true,
  Auditd::LogPriority $priority        = 'LOG_INFO',
  Auditd::LogFacility $facility        = 'LOG_LOCAL5'
) {
  simplib::assert_optional_dependency($module_name, 'simp/rsyslog')
  include '::rsyslog'
  include '::auditd::config::audisp_service'

  if $drop_audit_logs {
    # This will prevent audit records from being forwarded to remote
    # servers and/or written to local syslog files, but you still have
    # access to the records in the local audit log files.
    rsyslog::rule::drop { 'audispd':
      rule   => '$programname == \'audispd\''
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
