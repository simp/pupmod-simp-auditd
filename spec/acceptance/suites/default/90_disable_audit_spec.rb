require 'spec_helper_acceptance'
require 'yaml'

test_name 'disabling auditing via auditd class'

describe 'auditd class with simp auditd profile' do
  let(:enable_hieradata) do
    YAML.safe_load <<~HIERA
      ---
      pki::cacerts_sources:
      - 'file:///etc/pki/simp-testing/pki/cacerts'
      pki::private_key_source: 'file:///etc/pki/simp-testing/pki/private/%{facts.networking.fqdn}.pem'
      pki::public_key_source:  'file:///etc/pki/simp-testing/pki/public/%{facts.networking.fqdn}.pub'
    HIERA
  end

  let(:disable_hieradata) do
    YAML.safe_load <<~HIERA
      ---
      pki::cacerts_sources:
      - 'file:///etc/pki/simp-testing/pki/cacerts'
      pki::private_key_source: 'file:///etc/pki/simp-testing/pki/private/%{facts.networking.fqdn}.pem'
      pki::public_key_source:  'file:///etc/pki/simp-testing/pki/public/%{facts.networking.fqdn}.pub'
      auditd::enable: false
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
