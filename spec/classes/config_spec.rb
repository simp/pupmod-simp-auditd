require 'spec_helper'

# We have to test auditd::config via auditd, because auditd::config is
# private.  To take advantage of hooks built into puppet-rspec, the
# class described needs to be the class instantiated, i.e., auditd.
describe 'auditd' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts
        end

        context "with default parameters" do
          let(:params) {{ }}

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/etc/audit').with({
              :ensure  => 'directory',
              :owner   => 'root',
              :group   => 'root',
              :mode    => '0600',
              :recurse => true,
              :purge   => true
            })
          }
          it {
            is_expected.to contain_file('/etc/audit/rules.d').with({
              :ensure  => 'directory',
              :owner   => 'root',
              :group   => 'root',
              :mode    => '0600',
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

          if os_facts[:os][:release][:major] == '6'
            it { is_expected.to contain_augeas('auditd/USE_AUGENRULES').with_changes(
              ['set /files/etc/sysconfig/auditd/USE_AUGENRULES yes'])
            }
          else
            it { is_expected.to_not contain_augeas('auditd/USE_AUGENRULES') }
          end

          it { is_expected.to contain_class('auditd::config::audit_profiles') }
          it { is_expected.to contain_class('auditd::config::audit_profiles::simp') }
        end

        context 'with different log_group' do
          let(:params) {{ log_group: 'rspec' }}

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/etc/audit').with({
              :ensure  => 'directory',
              :owner   => 'root',
              :group   => 'rspec',
              :mode    => '0640',
              :recurse => true,
              :purge   => true
            })
          }
          it {
            is_expected.to contain_file('/etc/audit/rules.d').with({
              :ensure  => 'directory',
              :owner   => 'root',
              :group   => 'rspec',
              :mode    => '0640',
              :recurse => true,
              :purge   => true
            })
          }
          it {
            is_expected.to contain_file('/etc/audit/audit.rules').with({
              :owner => 'root',
              :group => 'rspec',
              :mode  => 'o-rwx'
            })
          }

          it {
            is_expected.to contain_file('/etc/audit/auditd.conf').with({
              :owner => 'root',
              :group => 'rspec',
              :mode  => '0640'
            })
          }

          it {
            is_expected.to contain_file('/var/log/audit').with({
              :ensure => 'directory',
              :owner  => 'root',
              :group  => 'rspec',
              :mode   => 'o-rwx'
            })
          }

          it {
            is_expected.to contain_file('/var/log/audit/audit.log').with({
              :owner  => 'root',
              :group  => 'rspec',
              :mode   => '0640'
            })
          }
        end

        context 'with empty default_audit_profiles' do
          let(:params) {{ :default_audit_profiles => [] }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to_not contain_class('auditd::config::audit_profiles') }
        end

        context 'with deprecated parameters' do
          context 'with default_audit_profile = true' do
            let(:params) {{ :default_audit_profile => true }}

            it { is_expected.to contain_class('auditd::config::audit_profiles') }
            it { is_expected.to contain_class('auditd::config::audit_profiles::simp') }
          end

          context 'with default_audit_profile = false' do
            let(:params) {{ :default_audit_profile => false }}

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to_not contain_class('auditd::config::audit_profiles') }
            it { is_expected.to_not contain_class('auditd::config::audit_profiles::simp') }
          end

          context "with default_audit_profile = 'simp'" do
            let(:params) {{ :default_audit_profile => 'simp' }}

            it { is_expected.to contain_class('auditd::config::audit_profiles') }
            it { is_expected.to contain_class('auditd::config::audit_profiles::simp') }
          end
        end
      end
    end
  end
end
