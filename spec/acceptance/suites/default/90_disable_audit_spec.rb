require 'spec_helper_acceptance'
require 'yaml'

test_name 'disabling auditing via auditd class'

describe 'auditd class with simp auditd profile' do
  let(:enable_hieradata) {
    YAML.load <<~HIERA
    ---
    pki::cacerts_sources:
    - 'file:///etc/pki/simp-testing/pki/cacerts'
    pki::private_key_source: 'file:///etc/pki/simp-testing/pki/private/%{fqdn}.pem'
    pki::public_key_source:  'file:///etc/pki/simp-testing/pki/public/%{fqdn}.pub'
    HIERA
  }

  let(:disable_hieradata) {
    YAML.load <<~HIERA
    ---
    pki::cacerts_sources:
    - 'file:///etc/pki/simp-testing/pki/cacerts'
    pki::private_key_source: 'file:///etc/pki/simp-testing/pki/private/%{fqdn}.pem'
    pki::public_key_source:  'file:///etc/pki/simp-testing/pki/public/%{fqdn}.pub'
    auditd::enable: false
    HIERA
  }

  let(:manifest) {
    <<-EOS
      class { 'auditd': }
    EOS
  }

  hosts.each do |host|
    context "on #{host}" do
      context 'ensure that auditing is enabled' do
        it 'should work with no errors' do
          set_hieradata_on(host, enable_hieradata)
          apply_manifest_on(host, manifest, :catch_failures => true)

          host.reboot
        end
      end

      context 'disabling auditd' do
        it 'should work with no errors' do
          set_hieradata_on(host, disable_hieradata)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should kill the auditd service' do
          result = YAML.safe_load(on(host, 'puppet resource service auditd --to_yaml').stdout)

          expect(result['service']['auditd']['ensure']).to eq('stopped')
          expect(result['service']['auditd']['enable']).to eq('false')
        end

        it 'should require reboot on subsequent run' do
          result = apply_manifest_on(host, manifest, :catch_failures => true)
          expect(result.output).to include('audit => modified')

          # Reboot to disable auditing in the kernel
          host.reboot
        end

        it 'should have kernel-level audit disabled on reboot' do
          retry_on(host, 'grep "audit=0" /proc/cmdline',
            { :max_retries => 30, :verbose => true }
          )
        end
      end
    end
  end
end
