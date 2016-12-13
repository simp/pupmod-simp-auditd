# This class is meant to be called from auditd.
# It ensures that logging rules are defined.
#
class auditd::config::logging {
  assert_private()

  contain '::auditd::config::audisp'
  contain '::auditd::config::audisp::syslog'
}
