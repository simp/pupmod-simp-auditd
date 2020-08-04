# _Description_
#
# Set a fact with all of the sample ruleset names if they exist on 
# the system for being able to utilize included rulesets
#
# Current output is hash containing:
# {
#   <policy_name>:
#     order: <policy_order>
# }
#
Facter.add('auditd_sample_rulesets') do
  confine :kernel => 'Linux'

  confine do
    File.exist?('/usr/share/audit/sample-rules')
  end

  setcode do
    retval = {}

    Dir['/usr/share/audit/sample-rules/*.rules'].map { |x|
      order, name = File.basename(x, '.rules').split('-', 2)
      retval[name] = { 'order' => order }
    }

    retval
  end
end
