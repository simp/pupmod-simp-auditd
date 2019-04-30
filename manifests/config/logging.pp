# NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# @summary Ensures that logging rules are defined.
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::logging {
  assert_private()

  contain '::auditd::config::audisp'
  contain '::auditd::config::audisp::syslog'
}
