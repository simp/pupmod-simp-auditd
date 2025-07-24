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
# @param bypass_kernel_check
#   Do not check to see if the kernel is enforcing auditing before trying to
#   manage the service.
#
#   * This may be required if auditing is not being actively managed in the
#     kernel and someone has stopped the auditd service by hand.
#
# @param warn_if_reboot_required
#   Add a ``reboot_notify`` warning if the system requires a reboot before the
#   service can be managed.
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::service (
  Variant[String[1],Boolean] $ensure                  = $auditd::enable,
  Boolean                    $enable                  = $auditd::enable,
  Boolean                    $warn_if_reboot_required = $auditd::warn_if_reboot_required
) {
  assert_private()

  if $warn_if_reboot_required {
    reboot_notify { "${auditd::service_name} service":
      reason => "The ${auditd::service_name} service cannot be started when the kernel is not enforcing auditing",
    }
  }
  else {
    # CCE-27058-7
    service { $auditd::service_name:
      ensure  => $ensure,
      enable  => $enable,
      stop    => "${auditd::auditctl_command} --signal stop",
      restart => "${auditd::auditctl_command} --signal stop; /usr/bin/systemctl start ${auditd::service_name}",
    }
  }
}
