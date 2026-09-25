# frozen_string_literal: true

# @summary The state of the audit subsystem on the running system
#
# Every key `auditctl -s` reports is included as-is, with Integer values
# converted to Integers. That includes `enabled`, the kernel's own flag:
#
# * `0` - auditing is disabled
# * `1` - auditing is enabled
# * `2` - auditing is enabled and the rule set is immutable (`-e 2`); rules
#   cannot change until the next reboot
#
# Added to those:
#
# * `version`          - the installed audit version, from `auditctl -v`
# * `immutable`        - `true` when `enabled` is `2`
# * `kernel_enforcing` - whether the kernel is auditing: `enabled` is non-zero,
#   or, when it is not, `audit=1` is on the kernel command line
# * `enforcing`        - whether the kernel is auditing and `auditd` is running
#
# `simplib__auditd` reports the same data when this module is installed, and
# keeps its own historical meaning of `enabled` (a Boolean that is `true` only
# for `1`).
#
# @see auditctl(8)
#
# @return [Hash]
#
# @example Output Hash
#
#   {
#     'enabled'          => 1,
#     'failure'          => 1,
#     'pid'              => 1234,
#     'backlog_limit'    => 8192,
#     ...
#     'version'          => '3.1.2',
#     'immutable'        => false,
#     'kernel_enforcing' => true,
#     'enforcing'        => true,
#   }
#
Facter.add('auditd_state') do
  confine kernel: 'Linux'

  auditctl = Facter::Core::Execution.which('auditctl')
  confine { auditctl }

  setcode do
    state = {}

    version = Facter::Core::Execution.execute("#{auditctl} -v", on_fail: nil).to_s.split(%r{\s+}).last
    state['version'] = version if version && !version.empty?

    # `auditctl -s` requires root; unreadable, the status keys are omitted.
    Facter::Core::Execution.execute("#{auditctl} -s", on_fail: nil).to_s.lines.each do |line|
      line = line.strip
      next if line.empty?

      key, value = line.split(%r{\s+}, 2)
      state[key] = Integer(value, exception: false) || value
    end

    enabled = state['enabled'].is_a?(Integer) ? state['enabled'] : 0

    state['immutable'] = enabled == 2

    if enabled.positive?
      state['kernel_enforcing'] = true

      ps = Facter::Core::Execution.which('ps')
      procs = ps ? Facter::Core::Execution.execute("#{ps} -e", on_fail: nil).to_s.lines : []
      state['enforcing'] = procs.any? { |x| x =~ %r{\sauditd\Z} }
    else
      cmdline = Facter.value('cmdline') || {}
      state['kernel_enforcing'] = cmdline['audit'].to_s == '1'
      state['enforcing'] = false
    end

    state
  end
end
