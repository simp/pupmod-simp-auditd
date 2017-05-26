require 'spec_helper_acceptance'

test_name 'auditd STIG enforcement'

describe 'auditd STIG enforcement' do

  def set_profile_data_on(host, hiera_yaml, profile_data)
    Dir.mktmpdir do |dir|
      tmp_yaml = File.join(dir, 'hiera.yaml')
      File.open(tmp_yaml, 'w') do |fh|
        fh.puts hiera_yaml
      end

      host.do_scp_to(tmp_yaml, '/etc/puppetlabs/puppet/hiera.yaml', {})
    end

    Dir.mktmpdir do |dir|
      File.open(File.join(dir, "default" + '.yaml'), 'w') do |fh|
        fh.puts(profile_data)
        fh.flush

        default_file = "/etc/puppetlabs/code/environments/production/hieradata/default.yaml"

        host.do_scp_to(dir + "/default.yaml", default_file, {})
      end
    end
  end

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

  let(:hiera_yaml) { <<-EOM
---
:backends:
  - yaml
  - simp_compliance_enforcement
:yaml:
  :datadir: "/etc/puppetlabs/code/environments/%{environment}/hieradata"
:simp_compliance_enforcement:
  :datadir: "/etc/puppetlabs/code/environments/%{environment}/hieradata"
:hierarchy:
  - default
:logger: console
    EOM
  }

  hosts.each do |host|
    context 'when enforcing the STIG' do
      # Using puppet_apply as a helper
      it 'should work with no errors' do
        set_profile_data_on(host, hiera_yaml, hieradata)
        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest, :catch_changes => true)
      end
    end
  end
end
