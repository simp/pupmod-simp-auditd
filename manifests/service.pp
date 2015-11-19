# == Class auditd::service
#
# This class is meant to be called from auditd.
# It ensure the service is running.
#
class auditd::service {
  assert_private()

  case $::operatingsystem {
    'RedHat','CentOS' : {
      # CCE-27058-7
      service { $::auditd::service_name:
        ensure     => 'running',
        enable     => true,
        hasrestart => true,
        hasstatus  => true,
        provider   => 'redhat'
      }

      # This is needed just in case the audit dispatcher fails at some point.
      exec { 'Restart Audispd':
        command => '/bin/true',
        unless  => "/usr/bin/pgrep -f ${::auditd::dispatcher}",
        notify  => Service[$::auditd::service_name]
      }
    }
    default : {
      fail("Error: ${::operatingsystem} is not yet supported by module '${module_name}'")
    }
  }
}
