require 'spec_helper'

describe 'auditd' do
  shared_examples_for 'a structured module' do
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

        context 'auditd with default parameters' do
          let(:params) {{ }}
          it_behaves_like 'a structured module'
          it {
            is_expected.to contain_service('auditd').with({
              :ensure  => 'running',
              :enable  => true,
              :start   => "/sbin/service auditd start",
              :stop    => "/sbin/service auditd stop",
              :restart => "/sbin/service auditd restart"
            })
          }
          it { is_expected.to contain_class('auditd::install').that_comes_before('Class[auditd::config::grub]') }
          it { is_expected.to contain_class('auditd::config::grub').with_enable(true) }
          it { is_expected.to_not contain_class('auditd::config::logging') }
          it { is_expected.to_not contain_class('auditd::config::audisp::syslog') }
        end

        context 'auditd with auditing disabled' do
          let(:params) {{
            :enable => false
          }}

          it { is_expected.to contain_class('auditd::config::grub').with_enable(false) }
          it { is_expected.to_not contain_class('auditd::install') }
          it { is_expected.to_not contain_class('auditd::config') }
          it { is_expected.to_not contain_class('auditd::service') }
        end

        context 'auditd with logging enabled' do
          let(:params) {{
            :syslog => true
          }}
          it { is_expected.to contain_class('auditd::config::logging') }
          it { is_expected.to contain_class('auditd::config::logging').that_notifies('Class[auditd::service]') }
          it { is_expected.to contain_class('auditd::config::audisp::syslog') }

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

      it { expect { is_expected.to contain_package('auditd') }.to raise_error(Puppet::Error) }
    end
  end
end
