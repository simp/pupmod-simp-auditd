require 'spec_helper_acceptance'
require 'yaml'

test_name 'disabling auditing via auditd class'

describe 'auditd class with simp auditd profile' do
  # 11.0.0 makes every resource opt-in: a bare `include auditd` installs the
  # package and nothing else, so the enabled state has to be asked for.
  let(:enable_hieradata) do
    YAML.safe_load <<~HIERA
      ---
      pki::cacerts_sources:
      - 'file:///etc/pki/simp-testing/pki/cacerts'
      pki::private_key_source: 'file:///etc/pki/simp-testing/pki/private/%{facts.networking.fqdn}.pem'
      pki::public_key_source:  'file:///etc/pki/simp-testing/pki/public/%{facts.networking.fqdn}.pub'
      auditd::default_audit_profiles: ['simp']
      auditd::purge_auditd_rules: true
      auditd::log_group: root
      auditd::config_group: root
      auditd::service_ensure: running
      auditd::service_enable: true
      auditd::at_boot: true
    HIERA
  end

  # Exercises the deprecated `auditd::enable` shim. It carries no service
  # keys on purpose: an explicit auditd::service_ensure overrides the shim
  # (init.pp:378-381), which would stop this from testing the shim at all.
  let(:disable_hieradata) do
    YAML.safe_load <<~HIERA
      ---
      pki::cacerts_sources:
      - 'file:///etc/pki/simp-testing/pki/cacerts'
      pki::private_key_source: 'file:///etc/pki/simp-testing/pki/private/%{facts.networking.fqdn}.pem'
      pki::public_key_source:  'file:///etc/pki/simp-testing/pki/public/%{facts.networking.fqdn}.pub'
      auditd::default_audit_profiles: ['simp']
      auditd::purge_auditd_rules: true
      auditd::log_group: root
      auditd::config_group: root
      auditd::enable: false
    HIERA
  end

  # The parameters that replace the shim. at_boot stays true: the kernel half
  # of disabling is already covered by the shim context below and by
  # 99_disable_audit_kernel_spec.rb, and flipping it here would leave the
  # following context starting from audit=0.
  let(:explicit_disable_hieradata) do
    YAML.safe_load <<~HIERA
      ---
      pki::cacerts_sources:
      - 'file:///etc/pki/simp-testing/pki/cacerts'
      pki::private_key_source: 'file:///etc/pki/simp-testing/pki/private/%{facts.networking.fqdn}.pem'
      pki::public_key_source:  'file:///etc/pki/simp-testing/pki/public/%{facts.networking.fqdn}.pub'
      auditd::default_audit_profiles: ['simp']
      auditd::purge_auditd_rules: true
      auditd::log_group: root
      auditd::config_group: root
      auditd::service_ensure: stopped
      auditd::service_enable: false
      auditd::at_boot: true
    HIERA
  end

  let(:manifest) do
    <<~EOS
      class { 'auditd': }
    EOS
  end

  hosts.each do |host|
    context "on #{host}" do
      context 'ensure that auditing is enabled' do
        it 'works with no errors' do
          set_hieradata_on(host, enable_hieradata)
          apply_manifest_on(host, manifest, catch_failures: true)
        end
      end

      # Covers disabling through the replacement parameters, so the suite
      # still tests this path once the `auditd::enable` shim is removed.
      # Restores the enabled state for the shim context that follows.
      context 'disabling auditd without the deprecated enable shim' do
        it 'works with no errors' do
          set_hieradata_on(host, explicit_disable_hieradata)
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'kills the auditd service' do
          result = YAML.safe_load(on(host, 'puppet resource service auditd --to_yaml').stdout)

          expect(result['service']['auditd']['ensure']).to eq('stopped')
          expect(result['service']['auditd']['enable']).to eq('false')
        end

        it 'restores the enabled state for the next context' do
          set_hieradata_on(host, enable_hieradata)
          apply_manifest_on(host, manifest, catch_failures: true)
        end
      end

      context 'disabling auditd' do
        it 'works with no errors' do
          set_hieradata_on(host, disable_hieradata)
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'kills the auditd service' do
          result = YAML.safe_load(on(host, 'puppet resource service auditd --to_yaml').stdout)

          expect(result['service']['auditd']['ensure']).to eq('stopped')
          expect(result['service']['auditd']['enable']).to eq('false')
        end

        it 'has kernel-level audit disabled on reboot' do
          apply_manifest_on(host, manifest, catch_failures: true)

          # Reboot to disable auditing in the kernel
          host.reboot

          retry_on(host, 'grep "audit=0" /proc/cmdline',
            { max_retries: 30, verbose: true })
        end
      end
    end
  end
end
