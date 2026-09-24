# NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# @summary Ensures that plugin for syslog is installed so audit events
#          can be sent to syslog in addition the audit partition.
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::logging {
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
  assert_private()

  # The auditd_version fact needs auditctl, which on EL10 comes from the
  # audit-rules package this module installs in the same run. Every supported
  # release ships audit 3 or later, so assume that until the fact says
  # otherwise rather than skipping the syslog plugin until the next run.
  if versioncmp(pick($facts['auditd_version'], '3.0'), '3.0') < 0 {
    contain 'auditd::config::audisp'
  }
  contain 'auditd::config::audisp::syslog'
}
