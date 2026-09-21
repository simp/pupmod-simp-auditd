# NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# @summary Ensure that the auditd service is running
#
# @param ensure
#   ``ensure`` state from the service resource
#
# @param enable
#   ``enable`` state from the service resource
#
# @param warn_if_reboot_required
#   Add a ``reboot_notify`` warning if the system requires a reboot before the
#   service can be managed.
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::service (
  Optional[Variant[String[1],Boolean]] $ensure                  = $auditd::_service_ensure,
  Optional[Boolean]                    $enable                  = $auditd::_service_enable,
  Boolean                              $warn_if_reboot_required = $auditd::warn_if_reboot_required
) {
  assert_private()

  if $warn_if_reboot_required {
    reboot_notify { "${auditd::service_name} service":
      reason => "The ${auditd::service_name} service cannot be started when the kernel is not enforcing auditing",
    }
  }
  elsif $ensure =~ NotUndef or $enable =~ NotUndef {
    # The service is only declared when a site says something about it. The
    # package enables and starts auditd itself, and taking ownership of the
    # service means every catalog run can stop or restart auditing on a host
    # that only wanted the package. Either attribute may be left undef, which
    # leaves that half of the service unmanaged.
    #
    # CCE-27058-7
    service { $auditd::service_name:
      ensure  => $ensure,
      enable  => $enable,
      stop    => "${auditd::auditctl_command} --signal stop",
      restart => "${auditd::auditctl_command} --signal stop; /usr/bin/systemctl start ${auditd::service_name}",
    }
  }
}
