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
#   Add a ``reboot_notify`` warning, instead of managing the service or
#   reloading rules, when the kernel is not enforcing auditing
#   (``auditd_state.kernel_enforcing`` is not ``true``). On a kernel that is
#   enforcing auditing this has no effect.
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

  # The fact reflects the running kernel at the start of the run, which is what
  # decides whether a rule load can take effect.
  $_immutable = fact('auditd_state.immutable') == true

  $_if_running = "/usr/bin/systemctl is-active --quiet ${auditd::service_name}"

  # auditd cannot be started until the kernel enforces auditing, which may
  # take a reboot. Only then does a warning replace managing the service: on a
  # kernel that is auditing, the service and reload branches below are what
  # load changed rules. An unknown kernel state (no auditctl yet, or facts
  # gathered as non-root) counts as not enforcing.
  if $warn_if_reboot_required and fact('auditd_state.kernel_enforcing') != true {
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
    # `auditctl --signal stop` only sends the daemon SIGTERM and returns. A
    # start issued before the daemon has exited finds the unit still active
    # and does nothing, and the daemon then exits, leaving auditd stopped.
    # (The unit sets RefuseManualStop, so systemd cannot stop it for us.)
    #
    # Wait until systemd's MainPID for the unit is no longer the old daemon's.
    # It changes when systemd has reaped that process, which is when a start
    # can take effect, and a daemon systemd itself restarted counts as gone.
    # When nothing is running there is nothing to stop or wait for.
    #
    # The restart fails, rather than carrying on, if the running daemon
    # cannot be signalled (a start would find it running and load nothing)
    # or has not exited after 30 seconds. The timeout covers the signal as
    # well as the wait: from audit 3.1.5 `auditctl --signal stop` itself
    # waits, without a limit, for the daemon to exit. The timeout only stops
    # a hung daemon from hanging the run. The restart succeeds only if auditd
    # is running at the end.
    $_main_pid = "/usr/bin/systemctl show --value -p MainPID ${auditd::service_name}"
    $_stop_and_wait = join([
        "/usr/bin/timeout 30 /bin/sh -c '${auditd::auditctl_command} --signal stop || exit 3",
        "while [ \"\$(${_main_pid})\" = \"\$1\" ]; do sleep 0.1; done' sh \"\$_pid\"",
    ], '; ')
    $_no_signal = "Could not signal ${auditd::service_name} to stop"
    $_no_exit = "${auditd::service_name} did not exit within 30 seconds"

    # CCE-27058-7
    service { $auditd::service_name:
      ensure  => $ensure,
      enable  => $enable,
      stop    => "${auditd::auditctl_command} --signal stop",
      restart => join([
          "_pid=\$(${_main_pid})",
          join([
              "if [ \"\$_pid\" != 0 ]; then ${_stop_and_wait}",
              "case \$? in 0) ;; 3) echo '${_no_signal}' >&2; exit 1 ;; *) echo '${_no_exit}' >&2; exit 1 ;; esac",
              'fi',
          ], '; '),
          "/usr/bin/systemctl start ${auditd::service_name} && ${_if_running}",
      ], '; '),
    }
  }
  elsif $reload_on_change {
    # Every file this module manages notifies this class, so a refresh here
    # means something on disk changed. With the service unmanaged, apply the
    # change to what is already running without taking ownership of the
    # service's state: nothing is started, stopped or enabled, and both
    # commands are skipped while auditd is not running.
    exec { 'auditd reload config':
      command     => "${auditd::auditctl_command} --signal reload",
      onlyif      => $_if_running,
      refreshonly => true,
    }

    # augenrules itself exits 0 without loading anything when the kernel is
    # immutable, so the load would report success while changing nothing. The
    # reboot_notify below takes its place.
    unless $_immutable {
      exec { 'auditd load rules':
        command     => '/usr/sbin/augenrules --load',
        onlyif      => $_if_running,
        # augenrules exits 1 if any rule was rejected, even when -c let the
        # rest load. -c is exactly the request to carry on past those.
        returns     => [0, 1],
        refreshonly => true,
      }
    }
  }

  # Whether rule changes are loaded by a service restart or by the reload
  # execs, an immutable rule set (-e 2) ignores them until the next boot. Say
  # so rather than let the restart or reload report success. This is not part
  # of the chain above: the kernel is enforcing auditing, so the
  # warn_if_reboot_required branch never applies, and a site that has asked
  # for neither the service nor reload_on_change has asked for no load.
  if $_immutable and ($ensure =~ NotUndef or $enable =~ NotUndef or $reload_on_change) {
    reboot_notify { "${auditd::service_name} rules":
      reason => 'The audit rules are immutable (-e 2); a reboot is required to load rule changes',
    }
  }
}
