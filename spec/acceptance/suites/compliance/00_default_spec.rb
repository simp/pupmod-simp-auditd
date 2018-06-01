require 'spec_helper_acceptance'

test_name 'auditd STIG enforcement'

describe 'auditd STIG enforcement' do

  let(:manifest) {
    <<-EOS
      include 'auditd'
    EOS
  }

  let(:hieradata) { <<-EOF
---
simp_options::pki: true
simp_options::pki::source: '/etc/pki/simp-testing/pki'

compliance_markup::enforcement:
  - disa_stig
  EOF
  }

  hosts.each do |host|

    let(:hiera_yaml) { <<-EOM
---
:backends:
  - yaml
  - simp_compliance_enforcement
:yaml:
  :datadir: "#{hiera_datadir(host)}"
:simp_compliance_enforcement:
  :datadir: "#{hiera_datadir(host)}"
:hierarchy:
  - default
:logger: console
      EOM
    }

    context 'when enforcing the STIG' do
      # Using puppet_apply as a helper
      it 'should work with no errors' do
        create_remote_file(host, host.puppet['hiera_config'], hiera_yaml)
        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should reboot to fully apply' do
        host.reboot
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest, :catch_changes => true)
      end
    end
  end
end
