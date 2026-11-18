require 'spec_helper_acceptance'

test_name 'auditd::rules'

# Each auditd::rules entry is its own file, so a later run that sets only some
# entries leaves the others in place, and only `ensure => absent` removes one.
describe 'auditd with rules' do
  let(:manifest) { "class { 'auditd': }" }

  let(:base_hieradata) do
    {
      'auditd::service_ensure' => 'running',
      'auditd::service_enable' => true,
    }
  end

  let(:identity) { { 'content' => ['-w /etc/group -p wa -k rules_hash_identity'] } }
  let(:time_change) { { 'content' => '-w /etc/localtime -p wa -k rules_hash_time_change' } }

  hosts.each do |host|
    context "on #{host}" do
      context 'with two entries' do
        it 'applies with no errors' do
          set_hieradata_on(host, base_hieradata.merge('auditd::rules' => { 'identity' => identity, 'time_change' => time_change }))
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, catch_changes: true)
        end

        # Only the files are checked: an earlier suite may have left the
        # kernel rule set immutable, which defers loading to a reboot.
        it 'writes both' do
          on(host, 'test -f /etc/audit/rules.d/75.identity.rules')
          on(host, 'test -f /etc/audit/rules.d/75.time_change.rules')
        end
      end

      context 'with only one of them set' do
        it 'applies with no errors' do
          set_hieradata_on(host, base_hieradata.merge('auditd::rules' => { 'time_change' => time_change }))
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'leaves the other one in place' do
          on(host, 'test -f /etc/audit/rules.d/75.identity.rules')
          expect(on(host, 'cat /etc/audit/rules.d/75.identity.rules').stdout).to include('-k rules_hash_identity')
        end
      end

      context 'with the other one absent' do
        it 'applies with no errors' do
          set_hieradata_on(host, base_hieradata.merge('auditd::rules' => { 'identity' => { 'ensure' => 'absent' }, 'time_change' => time_change }))
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'removes its file and keeps the rest' do
          on(host, 'test ! -e /etc/audit/rules.d/75.identity.rules')
          on(host, 'test -f /etc/audit/rules.d/75.time_change.rules')
        end
      end

      context 'cleaning up' do
        it 'removes the remaining file' do
          set_hieradata_on(host, base_hieradata.merge('auditd::rules' => { 'time_change' => { 'ensure' => 'absent' } }))
          apply_manifest_on(host, manifest, catch_failures: true)
          on(host, 'test ! -e /etc/audit/rules.d/75.time_change.rules')
        end
      end
    end
  end
end
