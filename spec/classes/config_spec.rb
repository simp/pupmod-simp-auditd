require 'spec_helper'

describe 'auditd::config' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
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
              :mode  => 'o-rwx'
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

          it {
            is_expected.to contain_file('/var/log/audit/audit.log').with({
              :owner  => 'root',
              :group  => 'root',
              :mode   => '0600'
            })
          }

          if facts[:os][:release][:major] == '6'
            it { is_expected.to contain_augeas('auditd/USE_AUGENRULES').with_changes(
              ['set /files/etc/sysconfig/auditd/USE_AUGENRULES yes'])
            }
          else
            it { is_expected.to_not contain_augeas('auditd/USE_AUGENRULES') }
          end
        end
      end
    end
  end
end
