require 'spec_helper'

describe 'auditd' do
  shared_examples_for "a structured module" do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('auditd') }
    it { is_expected.to contain_class('auditd') }
    it { is_expected.to contain_class('auditd::install').that_comes_before('Class[auditd::config]') }
    it { is_expected.to contain_class('auditd::config') }
    it { is_expected.to contain_class('auditd::service').that_subscribes_to('Class[auditd::config]') }
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts
        end

        context "auditd without default parameters" do
          let(:params) {{ }}
          it_behaves_like "a structured module"
          it {
            is_expected.to contain_service('auditd').with({
              :ensure => 'running',
              :enable => true,
              :hasrestart => true,
              :hasstatus => true,
              # This is because the default provider for RHEL7 uses systemd
              # which does not work for auditd at this time.
              :provider => 'redhat'
            })
          }
          it { is_expected.to contain_class('auditd::install').that_comes_before('Class[auditd::config::grub]') }
          it { is_expected.to contain_class('auditd::config::grub').with_enable(true) }
        end

        context "auditd with auditing disabled" do
          let(:params) {{
            :enable => false
          }}

          it { is_expected.to contain_class('auditd::config::grub').with_enable(false) }
          it { is_expected.to_not contain_class('auditd::install') }
          it { is_expected.to_not contain_class('auditd::config') }
          it { is_expected.to_not contain_class('auditd::service') }
        end

        context "auditd with logging enabled" do
          let(:params) {{
            :syslog => true
          }}
          it { is_expected.to contain_class('auditd::config::logging') }
          it { is_expected.to contain_class('auditd::config::logging').that_notifies('Class[auditd::service]') }
        end
      end
    end
  end

  context 'unsupported operating system' do
    describe 'auditd without any parameters on Solaris/Nexenta' do
      let(:facts) {
        os_facts = {}
        os_facts[:os]         = {}
        os_facts[:os]['name'] = 'Solaris'

        os_facts
      }

      it { expect { is_expected.to contain_package('auditd') }.to raise_error(Puppet::Error, /.*Solaris.* not supported/) }
    end
  end
end
