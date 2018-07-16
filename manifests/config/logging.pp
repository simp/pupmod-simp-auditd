# NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# It ensures that logging rules are defined.
#
class auditd::config::logging {
  assert_private()

  contain '::auditd::config::audisp'
  contain '::auditd::config::audisp::syslog'
}
