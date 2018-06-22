# This class is called from auditd for service config.
#
class auditd::config {

  assert_private()

  if $::auditd::default_audit_profile != undef {
    deprecation('auditd::default_audit_profile',
      "'auditd::default_audit_profile' is deprecated. Use 'auditd::default_audit_profiles' instead")
    if $::auditd::default_audit_profile {
      $profiles = [ 'simp' ]
    } else {
      $profiles = []
    }
  } else {
    $profiles = $::auditd::default_audit_profiles
  }

  file { '/etc/audit/rules.d':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
    recurse => true,
    purge   => true
  }

  file { '/etc/audit/audit.rules':
    owner => 'root',
    group => 'root',
    mode  => 'o-rwx'
  }

  file { '/etc/audit/auditd.conf':
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => epp("${module_name}/etc/audit/auditd.conf.epp")
  }

  file { '/var/log/audit':
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => 'o-rwx'
  }

  file { $::auditd::log_file:
    owner => 'root',
    group => 'root',
    mode  => '0600'
  }

  if ($facts['os']['release']['major'] < '7') {
    # make sure audit.rules is regenerated every time the
    # service is started
    augeas { 'auditd/USE_AUGENRULES':
      changes => [
        'set /files/etc/sysconfig/auditd/USE_AUGENRULES yes',
      ],
    }
  }

  unless empty($profiles) {
    # use contain instead of include so that config file changes can
    # notify auditd::service class
    contain 'auditd::config::audit_profiles'
  }

}
