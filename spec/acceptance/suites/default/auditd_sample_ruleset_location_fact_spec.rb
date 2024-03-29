require 'spec_helper_acceptance'

test_name 'auditd_sample_ruleset_location fact'

describe 'auditd_sample_ruleset_location fact' do

  hosts.each do |host|
    it 'Auditd sample ruleset location should be gathered' do
      fact_info = pfact_on(host, 'auditd_sample_ruleset_location')

      expect(fact_info).to match(/\/usr\/share\/(doc\/)*audit(-*\d*.\d*.\d*)*\/(sample-)*rules/)
    end
  end
end