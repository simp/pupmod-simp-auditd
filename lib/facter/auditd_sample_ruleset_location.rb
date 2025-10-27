# _Description_
#
# Set a fact with the location of the audit sample rules
#
# Current output is a string containing the location of the audit sample rules
#
Facter.add('auditd_sample_ruleset_location') do
  confine kernel: 'Linux'

  setcode do
    candidates = [
      '/usr/share/audit/sample-rules',
      '/usr/share/audit-rules',
      '/usr/share/doc/auditd/examples/rules',
    ] + Dir.glob('/usr/share/doc/audit*/rules')

    candidates.find { |d| File.directory?(d) && !Dir.glob("#{d}/*.rules").empty? }
  end
end
