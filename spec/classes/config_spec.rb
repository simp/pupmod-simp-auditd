require 'spec_helper'

describe 'auditd::config' do
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

        context "auditd::config without any parameters" do
          let(:params) {{ }}
          it { is_expected.to contain_class('auditd::config::audit_profiles::simp') }
          it {
            is_expected.to contain_file('/etc/audit/rules.d').with({
              :ensure  => 'directory',
              :owner   => 'root',
              :group   => 'root',
              :mode    => '0640',
              :recurse => true,
              :purge   => true
            })
          }
          it {
            is_expected.to contain_file('/etc/audit/audit.rules').with({
              :owner => 'root',
              :group => 'root',
              :mode  => '0600'
            })
          }

          it {
            is_expected.to contain_file('/etc/audit/auditd.conf').with({
              :owner => 'root',
              :group => 'root',
              :mode  => '0600'
            })

            # Make sure that we don't have any entries that have a misspelled
            # variable.
            is_expected.not_to contain_file('/etc/audit/auditd.conf').with_content(%r(^.+\s+=\s+(\s+|$)))
          }

          it {
            is_expected.to contain_file('/var/log/audit').with({
              :ensure => 'directory',
              :owner  => 'root',
              :group  => 'root',
              :mode   => 'o-rwx'
            })
          }
        end
      end
    end
  end
end
