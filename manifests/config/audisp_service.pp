# Make sure the audispd process keeps running.
#
# Should only be called from audisp processing services.
#
class auditd::config::audisp_service {
  assert_private()

  # This is needed just in case the audit dispatcher fails at some point.
  exec { 'Restart Audispd':
    command => '/bin/true',
    unless  => "/usr/bin/pgrep -f ${::auditd::dispatcher}",
    notify  => Service[$::auditd::service_name]
  }
}
