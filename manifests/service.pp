# NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# Ensure that the service is running
#
# @param ensure
#   ``ensure`` state from the service resource
#
# @param enable
#   ``enable`` state from the service resource
#
class auditd::service (
  $ensure = 'running',
  $enable = true
){
  assert_private()

  # CCE-27058-7
  service { $::auditd::service_name:
    ensure     => $ensure,
    enable     => $enable,
    hasrestart => true,
    hasstatus  => true,
    provider   => 'redhat'
  }
}
