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
        [{ :auditd_version => '3.0', :auditd_major_version => '3'}, { :auditd_version => '2.8.5', :auditd_major_version => '2'}].each do |  more_facts |
          context "with auditd version #{more_facts[:auditd_major_version]}" do
            let(:facts) {os_facts.merge(more_facts)}

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
              it { is_expected.to_not contain_class('auditd::config::plugin::syslog') }
            end

            context 'auditd with space_left < admin_space_left' do
              let(:params) {{
                :space_left       => 20,
                :admin_space_left => 25
              }}

              it { is_expected.to compile.and_raise_error(/Auditd requires \$space_left to be greater than \$admin_space_left, otherwise it will not start/) }
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
                :manage_syslog_plugin => true
              }}
              it { is_expected.to contain_class('auditd::config::logging') }
              it { is_expected.to contain_class('auditd::config::logging').that_notifies('Class[auditd::service]') }
              # Test private class config::logging
              it {
                if facts[:auditd_major_version] >= '3'
                  is_expected.to_not contain_class('auditd::config::audisp')
                else
                  is_expected.to contain_class('auditd::config::audisp')
                end
              }
              it { is_expected.to contain_class('auditd::config::plugins::syslog') }
            end
          end
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
