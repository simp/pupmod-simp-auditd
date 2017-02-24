# This class is meant to be called from auditd.
# It ensure the service is running.
#
class auditd::service {
  assert_private()

  case $facts['os']['name'] {
    'RedHat','CentOS' : {
      # CCE-27058-7
      service { $::auditd::service_name:
        ensure     => 'running',
        enable     => true,
        hasrestart => true,
        hasstatus  => true,
        provider   => 'redhat'
      }
    }
    default : {
      fail("Error: ${facts['os']['name']} is not yet supported by module '${module_name}'")
    }
  }
}
