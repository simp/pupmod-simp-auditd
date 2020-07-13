require 'spec_helper'

# We have to test auditd::config::sample_rulesets via auditd, because
# auditd::config::sample_rulesets is private.  To take advantage of hooks
# built into puppet-rspec, the class described needs to be the class
# instantiated, i.e., auditd.
describe 'auditd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts){
        _facts = Marshal.load(Marshal.dump(os_facts))
        unless _facts[:auditd_major_version]
          if _facts[:os][:release][:major] < '8'
            _facts[:auditd_major_version] = '2'
          else
            _facts[:auditd_major_version] = '3'
            _facts[:auditd_sample_rulesets] = {
              'base-config' => { 'order' => 10, },
              'no-audit'    => { 'order' => 10, },
              'loginuid'    => { 'order' => 11, },
              'stig'        => { 'order' => 30, },
              'privileged'  => { 'order' => 31, },
              'networking'  => { 'order' => 71, },
              'finalize'    => { 'order' => 99, },
            }
          end
        end

        _facts
      }

      context 'with default parameters' do
        it { is_expected.to compile.with_all_deps }
      end

      context 'with non-privileged sample rulesets and one invalid sample' do
        let(:params) {{
          :sample_rulesets => [
            'base-config',
            'no-audit',
            'finalize',
            'bad_sample_set',
          ]
        }}

        it {
          if facts[:auditd_major_version] == '3'
            is_expected.to compile.with_all_deps
            is_expected.to contain_file('/etc/audit/rules.d/10-base-config.rules').with({
              :ensure => 'file',
              :source => 'file:///usr/share/audit/sample-rules/10-base-config.rules',
            }).that_notifies('Class[auditd::service]')

            is_expected.to contain_file('/etc/audit/rules.d/10-no-audit.rules').with({
              :ensure => 'file',
              :source => 'file:///usr/share/audit/sample-rules/10-no-audit.rules',
            }).that_notifies('Class[auditd::service]')

            is_expected.to contain_file('/etc/audit/rules.d/99-finalize.rules').with({
              :ensure => 'file',
              :source => 'file:///usr/share/audit/sample-rules/99-finalize.rules',
            }).that_notifies('Class[auditd::service]')

            is_expected.to contain_notify('bad_sample_set not found')
          else
            is_expected.to compile.with_all_deps
            is_expected.to_not contain_file('/etc/audit/rules.d/10-base-config.rules')
            is_expected.to_not contain_file('/etc/audit/rules.d/10-no-audit.rules')
            is_expected.to_not contain_file('/etc/audit/rules.d/99-finalize.rules')
            is_expected.to_not contain_notify('bad_sample_set not found')
          end
        }
      end

      context 'with privileged sample ruleset' do
        let(:params) {{
          :sample_rulesets => [
            'privileged'
          ]
        }}

        it {
          if facts[:auditd_major_version] == '3'
            is_expected.to compile.with_all_deps
            is_expected.to contain_exec('generate_privileged_script').with({
              :command => "sha512sum /usr/share/audit/sample-rules/31-privileged.rules > /usr/share/audit/sample-rules/.31-privileged.rules.sha512 && sed -e 's|^#||' -e 's|>[[:space:]][[:alnum:]]*.rules|> /usr/share/audit/sample-rules/31-privileged.rules.evaluated|' /usr/share/audit/sample-rules/31-privileged.rules > /usr/local/sbin/generate_privileged_audit_sample_rules.sh",
              :path    => ['/usr/bin', '/usr/sbin', '/bin', '/sbin'],
              :unless  => [
                'test -f /usr/share/audit/sample-rules/.31-privileged.rules.sha512',
                'sha512sum -c --status /usr/share/audit/sample-rules/.31-privileged.rules.sha512'
              ],
            }).that_notifies('Exec[build_privileged_ruleset]')

            is_expected.to contain_exec('build_privileged_ruleset').with({
              :command     => '/bin/bash "/usr/local/sbin/generate_privileged_audit_sample_rules.sh"',
              :refreshonly => true,
            })

            is_expected.to contain_file('/etc/audit/rules.d/31-privileged.rules').with({
              :ensure => 'file',
              :source => 'file:///usr/share/audit/sample-rules/31-privileged.rules.evaluated',
            }).that_notifies('Class[auditd::service]').that_requires('Exec[build_privileged_ruleset]')
          else
            is_expected.to compile.with_all_deps
            is_expected.to_not contain_exec('generate_privileged_script')
            is_expected.to_not contain_exec('build_privileged_ruleset')
            is_expected.to_not contain_file('/etc/audit/rules.d/31-privileged.rules')
          end
        }
      end
    end
  end
end
