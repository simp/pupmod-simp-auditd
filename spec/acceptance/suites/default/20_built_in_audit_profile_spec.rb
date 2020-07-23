require 'spec_helper_acceptance'

test_name 'auditd class with sample rulesets'

# The fundamental module capabilities are tested in 00_base_spec.rb and
# 99_disable_audit_kernel_spec.rb.  The purpose of the tests in this
# file this is to verify each profile generates valid audit rules.
#
describe 'auditd class with sample rulesets' do
  require_relative('lib/util')

  let(:hieradata) {
    {
      'pki::cacerts_sources'    => ['file:///etc/pki/simp-testing/pki/cacerts'] ,
      'pki::private_key_source' => "file:///etc/pki/simp-testing/pki/private/%{fqdn}.pem",
      'pki::public_key_source'  => "file:///etc/pki/simp-testing/pki/public/%{fqdn}.pub",
    }
  }

  let(:enable_stig_sample_rulesets) {
    {
      'auditd::default_audit_profiles' => [
        'built_in',
      ],
      'auditd::config::audit_profiles::built_in::rulesets' => [
        'base-config',
        'stig',
        'finalize',
      ],
    }.merge(hieradata)
  }

  let(:multiple_profiles) {
    {
      'auditd::default_audit_profiles' => [
        'built_in',
        'simp',
      ],
      'auditd::config::audit_profiles::built_in::rulesets' => [
        'base-config',
        'stig',
        'finalize',
      ],
    }
  }

  let(:enable_ospp_rulesets) {
    {
      'auditd::default_audit_profiles' => [
        'built_in',
      ],
      'auditd::config::audit_profiles::built_in::rulesets' => [
        'base-config',
        'loginuid',
        'ospp-v42-1-create-failed',
        'ospp-v42-1-create-success',
        'ospp-v42-2-modify-failed',
        'ospp-v42-2-modify-success',
        'ospp-v42-3-access-failed',
        'ospp-v42-3-access-success',
        'ospp-v42-4-delete-failed',
        'ospp-v42-4-delete-success',
        'ospp-v42-5-perm-change-failed',
        'ospp-v42-5-perm-change-success',
        'ospp-v42-6-owner-change-failed',
        'ospp-v42-6-owner-change-success',
        'ospp-v42',
      ],
    }
  }

  let(:enable_privileged_ruleset) {
    {
      'auditd::default_audit_profiles' => [
        'built_in',
      ],
      'auditd::config::audit_profiles::built_in::rulesets' => [
        'privileged'
      ],
    }.merge(hieradata)
  }

  let(:manifest) {
    <<-EOS
      class { 'auditd': }
    EOS
  }

  hosts_with_role(hosts, 'el8').each do |host|
    # Ensure audit is at latest, since this will not test anything if not
    upgrade_package(host, 'audit')

    context "on #{host}" do

      context 'with stig profile from sample rulesets' do
        it 'should work with no errors' do
          set_hieradata_on(host, enable_stig_sample_rulesets)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be running the auditd service' do
          result = YAML.safe_load(on(host, 'puppet resource service auditd --to_yaml').stdout)
          expect(result['service']['auditd']['ensure']).to eq('running')
        end

        it 'should load valid rules' do
          # make sure the rules have been regenerated
          # (search for rule only contained in new rule set)
          retry_on(host, 'grep renameat /etc/audit/audit.rules | grep delete',
            { :max_retries => 30, :verbose => true })

          results = AuditdTestUtil::AuditdRules.new(host)

          expect(results.rules).to_not be_empty
          expect(results.warnings).to eq([])
          expect(results.errors).to eq([])
        end
      end

      context 'with ospp enabled from sample rulesets' do
        it 'should work with no errors' do
          set_hieradata_on(host, enable_ospp_rulesets)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be running the auditd service' do
          result = YAML.safe_load(on(host, 'puppet resource service auditd --to_yaml').stdout)
          expect(result['service']['auditd']['ensure']).to eq('running')
        end


        it 'should load valid rules' do
          # make sure the rules have been regenerated
          # (search for tag only contained in new rule set)
          retry_on(host, 'grep selinux /etc/audit/audit.rules | grep MAC-policy',
            { :max_retries => 30, :verbose => true })


          results = AuditdTestUtil::AuditdRules.new(host)

          expect(results.rules).to_not be_empty
          expect(results.warnings).to eq([])
          expect(results.errors).to eq([])
        end
      end

      context 'with privileged sample ruleset' do
        it 'should work with no errors' do
          set_hieradata_on(host, enable_privileged_ruleset)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be running the auditd service' do
          result = YAML.safe_load(on(host, 'puppet resource service auditd --to_yaml').stdout)
          expect(result['service']['auditd']['ensure']).to eq('running')
        end


        it 'should load valid rules' do
          # make sure the rules have been regenerated
          # (search for tag only contained in new rule set)
          retry_on(host, 'grep umount /etc/audit/audit.rules | grep privileged',
            { :max_retries => 30, :verbose => true })


          results = AuditdTestUtil::AuditdRules.new(host)

          expect(results.rules).to_not be_empty
          expect(results.warnings).to eq([])
          expect(results.errors).to eq([])
        end
      end

      context 'with built_in and simp profiles' do
        it 'should work with no errors' do
          set_hieradata_on(host, multiple_profiles)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be running the auditd service' do
          result = YAML.safe_load(on(host, 'puppet resource service auditd --to_yaml').stdout)
          expect(result['service']['auditd']['ensure']).to eq('running')
        end

        it 'should load valid rules' do
          # make sure the rules have been regenerated
          # (search for rule only contained in new rule set)
          retry_on(host, 'grep renameat /etc/audit/audit.rules | grep delete',
            { :max_retries => 30, :verbose => true })

          results = AuditdTestUtil::AuditdRules.new(host)

          expect(results.rules).to_not be_empty
          expect(results.warnings).to eq([])
          expect(results.errors).to eq([])
        end
      end
    end
  end
end
