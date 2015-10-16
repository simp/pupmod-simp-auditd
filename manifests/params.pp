# == Class auditd::params
#
# This class is meant to be called from auditd.
# It sets variables according to platform.
#
class auditd::params {
  case $::osfamily {
    'RedHat': {
      $package_name = 'audit'
      $service_name = 'auditd'
    }
    default: {
      fail("${::operatingsystem} not supported")
    }
  }
}
