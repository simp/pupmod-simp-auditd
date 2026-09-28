# _Description_
#
# Set a fact to return the version of auditd that is installed.
# This is useful for applying the correct configuration file options.
#
Facter.add('auditd_version') do
  confine kernel: 'Linux'

  setcode do
    Facter.value('auditd_state')&.fetch('version', nil)
  end
end

Facter.add('auditd_major_version') do
  confine kernel: 'Linux'

  setcode do
    auditd_version = Facter.value('auditd_version')
    auditd_version&.split('.')&.first
  end
end

Facter.add('auditd_auditctl_cmd') do
  confine kernel: 'Linux'

  setcode do
    Facter::Util::Resolution.which('auditctl')
  end
end
