# This class is meant to be called from auditd.
# It sets variables according to platform.
#
class auditd::params {
  if $::operatingsystem in ['RedHat','CentOS'] {
    $package_name = 'audit'
    $service_name = 'auditd'
  }
  else {
    fail("${::operatingsystem} not supported")
  }
}
