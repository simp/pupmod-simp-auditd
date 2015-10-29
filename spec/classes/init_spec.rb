require 'spec_helper'

describe 'auditd' do
  shared_examples_for "a structured module" do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('auditd') }
    it { is_expected.to contain_class('auditd') }
    it { is_expected.to contain_class('auditd::params') }
    it { is_expected.to contain_class('auditd::install').that_comes_before('auditd::config') }
    it { is_expected.to contain_class('auditd::config') }
    it { is_expected.to contain_class('auditd::service').that_subscribes_to('auditd::config') }
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          if ['RedHat','CentOS'].include?(facts[:operatingsystem]) && facts[:operatingsystemmajrelease].to_s < '7'
            facts[:apache_version] = '2.2'
            facts[:grub_version] = '0.9'
          else
            facts[:apache_version] = '2.4'
            facts[:grub_version] = '2.0~beta'
          end

          facts
        end

        context "auditd without any parameters" do
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
        end

        context "auditd with auditing enabled" do
          let(:params) {{
            :enable_auditing => true
          }}

          it { is_expected.to contain_class('auditd::install').that_comes_before('auditd::config::grub') }
        end

        context "auditd with auditing disabled" do
          let(:params) {{
            :enable_auditing => false
          }}

          it { is_expected.to contain_class('auditd::config::grub').with_enable(false) }
          it { is_expected.not_to contain_class('auditd::install') }
        end

        context "auditd with logging enabled" do
          let(:params) {{
            # Change to this after the refactor
            # :enable_logging => true
            :to_syslog => true
          }}
          it { is_expected.to contain_class('auditd::config::logging') }
          it { is_expected.to contain_class('auditd::config::logging').that_notifies('auditd::service') }
        end
      end
    end
  end

  context 'unsupported operating system' do
    describe 'auditd without any parameters on Solaris/Nexenta' do
      let(:facts) {{
        :osfamily        => 'Solaris',
        :operatingsystem => 'Nexenta',
      }}

      it { expect { is_expected.to contain_package('auditd') }.to raise_error(Puppet::Error, /Nexenta not supported/) }
    end
  end
end
