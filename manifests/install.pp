# == Class auditd::install
#
# This class is called from auditd for install.
#
class auditd::install {
  assert_private()

  package { $::auditd::package_name:
    ensure => $::auditd::package_ensure
  }
}
