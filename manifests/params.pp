# This class is meant to be called from auditd.
# It sets variables according to platform.
#
class auditd::params {
  if $facts['os']['name'] in ['RedHat','CentOS'] {
    $package_name = 'audit'
    $service_name = 'auditd'
  }
  else {
    fail("${facts['os']['name']} not supported")
  }
}
