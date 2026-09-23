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
# @param reload_on_change
#   Load changes into the running system when the service is not managed.
#   @see `auditd::reload_on_change`
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::service (
  Optional[Variant[String[1],Boolean]] $ensure                  = $auditd::_service_ensure,
  Optional[Boolean]                    $enable                  = $auditd::_service_enable,
  Boolean                              $warn_if_reboot_required = $auditd::warn_if_reboot_required,
  Boolean                              $reload_on_change        = $auditd::reload_on_change,
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
  elsif $reload_on_change {
    # Every file this module manages notifies this class, so a refresh here
    # means something on disk changed. With the service unmanaged, apply the
    # change to what is already running without taking ownership of the
    # service's state: nothing is started, stopped or enabled, and both
    # commands are skipped while auditd is not running.
    $_if_running = "/usr/bin/systemctl is-active --quiet ${auditd::service_name}"

    exec { 'auditd reload config':
      command     => "${auditd::auditctl_command} --signal reload",
      onlyif      => $_if_running,
      refreshonly => true,
    }

    # augenrules itself exits 0 without loading anything when the kernel is
    # immutable, so the load would report success while changing nothing. The
    # fact reflects the running kernel at the start of the run, which is what
    # decides whether a load can take effect.
    if fact('auditd_state.immutable') == true {
      reboot_notify { "${auditd::service_name} rules":
        reason => 'The audit rules are immutable (-e 2); a reboot is required to load rule changes',
      }
    }
    else {
      exec { 'auditd load rules':
        command     => '/usr/sbin/augenrules --load',
        onlyif      => $_if_running,
        refreshonly => true,
      }
    }
  }
}
