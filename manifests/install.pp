# NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# Install the auditd packages
#
class auditd::install {
  assert_private()

  package { $::auditd::package_name:
    ensure => $::auditd::package_ensure
  }
}
