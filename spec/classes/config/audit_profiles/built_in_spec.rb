require 'spec_helper'

# We have to test auditd::config::audit_profiles::built_in via auditd,
# because auditd::config::audit_profiles::built_in is private.  To take
# advantage of hooks built into puppet-rspec, the class described needs
# to be the class instantiated, i.e., auditd. Then, to adjust the
# private class's parameters, we will use hieradata.
describe 'auditd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        _facts = Marshal.load(Marshal.dump(os_facts))
        if _facts[:os][:release][:major] < '8'
          _facts[:auditd_major_version] = '2'
          _facts[:auditd_sample_ruleset_location] = '/usr/share/doc/audit-2.8.5/rules'
        else
          _facts[:auditd_major_version] = '3'
          _facts[:auditd_sample_ruleset_location] = '/usr/share/audit/sample-rules'
        end
        _facts[:auditd_sample_rulesets] = {
          'base-config' => { 'order' => 10, },
                    'no-audit'    => { 'order' => 10, },
                    'loginuid'    => { 'order' => 11, },
                    'stig'        => { 'order' => 30, },
                    'privileged'  => { 'order' => 31, },
                    'networking'  => { 'order' => 71, },
                    'finalize'    => { 'order' => 99, },
        }

        _facts
      end

      context 'with default parameters' do
        it { is_expected.to compile.with_all_deps }
      end

      context 'with non-privileged sample rulesets and one invalid sample' do
        let(:params) do
          {
            default_audit_profiles: [
              'built_in',
            ]
          }
        end

        let(:hieradata) { 'built_in_audit_profile/random_sample_rulesets' }

        it {
          # We should not have the items included in audit_profiles since we are
          # only defining `built_in`
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(%r{^-i$})
          is_expected.not_to contain_file('/etc/audit/rules.d/05_default_drop.rules')
          is_expected.not_to contain_file('/etc/audit/rules.d/99_tail.rules')

          is_expected.to compile.with_all_deps
          if facts[:auditd_major_version] == '3'
            is_expected.to contain_file('/etc/audit/rules.d/10-base-config.rules').with({
                                                                                          ensure: 'file',
              source: 'file:///usr/share/audit/sample-rules/10-base-config.rules',
                                                                                        }).that_notifies('Class[auditd::service]')

            is_expected.to contain_file('/etc/audit/rules.d/10-no-audit.rules').with({
                                                                                       ensure: 'file',
              source: 'file:///usr/share/audit/sample-rules/10-no-audit.rules',
                                                                                     }).that_notifies('Class[auditd::service]')

            is_expected.to contain_file('/etc/audit/rules.d/99-finalize.rules').with({
                                                                                       ensure: 'file',
              source: 'file:///usr/share/audit/sample-rules/99-finalize.rules',
                                                                                     }).that_notifies('Class[auditd::service]')

            is_expected.to contain_notify('bad_sample_set not found')
          else
            is_expected.to contain_file('/etc/audit/rules.d/10-base-config.rules').with({
                                                                                          ensure: 'file',
              source: 'file:///usr/share/doc/audit-2.8.5/rules/10-base-config.rules',
                                                                                        }).that_notifies('Class[auditd::service]')

            is_expected.to contain_file('/etc/audit/rules.d/10-no-audit.rules').with({
                                                                                       ensure: 'file',
              source: 'file:///usr/share/doc/audit-2.8.5/rules/10-no-audit.rules',
                                                                                     }).that_notifies('Class[auditd::service]')

            is_expected.to contain_file('/etc/audit/rules.d/99-finalize.rules').with({
                                                                                       ensure: 'file',
              source: 'file:///usr/share/doc/audit-2.8.5/rules/99-finalize.rules',
                                                                                     }).that_notifies('Class[auditd::service]')
          end
        }
      end

      context 'with privileged sample ruleset' do
        let(:params) do
          {
            default_audit_profiles: [
              'built_in',
            ],
          }
        end

        let(:hieradata) { 'built_in_audit_profile/privileged_ruleset' }

        it {
          # We should not have the items included in audit_profiles since we are
          # only defining `built_in`
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(%r{^-i$})
          is_expected.not_to contain_file('/etc/audit/rules.d/05_default_drop.rules')
          is_expected.not_to contain_file('/etc/audit/rules.d/99_tail.rules')

          is_expected.to compile.with_all_deps
          if facts[:auditd_major_version] == '3'
            is_expected.to contain_exec('generate_privileged_script').with({
                                                                             command: "sha512sum /usr/share/audit/sample-rules/31-privileged.rules > /usr/share/audit/sample-rules/.31-privileged.rules.sha512 && sed -e 's|^#||' -e 's|>[[:space:]][[:alnum:]]*.rules|> /usr/share/audit/sample-rules/31-privileged.rules.evaluated|' /usr/share/audit/sample-rules/31-privileged.rules > /usr/local/sbin/generate_privileged_audit_sample_rules.sh",
              path: ['/usr/bin', '/usr/sbin', '/bin', '/sbin'],
              unless: [
                'test -f /usr/share/audit/sample-rules/.31-privileged.rules.sha512',
                'sha512sum -c --status /usr/share/audit/sample-rules/.31-privileged.rules.sha512',
              ],
                                                                           }).that_notifies('Exec[build_privileged_ruleset]')

            is_expected.to contain_exec('build_privileged_ruleset').with({
                                                                           command: '/bin/bash "/usr/local/sbin/generate_privileged_audit_sample_rules.sh"',
              refreshonly: true,
                                                                         })

            is_expected.to contain_file('/etc/audit/rules.d/31-privileged.rules').with({
                                                                                         ensure: 'file',
              source: 'file:///usr/share/audit/sample-rules/31-privileged.rules.evaluated',
                                                                                       }).that_notifies('Class[auditd::service]').that_requires('Exec[build_privileged_ruleset]')
          else
            is_expected.to contain_exec('generate_privileged_script').with({
                                                                             command: "sha512sum /usr/share/doc/audit-2.8.5/rules/31-privileged.rules > /usr/share/doc/audit-2.8.5/rules/.31-privileged.rules.sha512 && sed -e 's|^#||' -e 's|>[[:space:]][[:alnum:]]*.rules|> /usr/share/doc/audit-2.8.5/rules/31-privileged.rules.evaluated|' /usr/share/doc/audit-2.8.5/rules/31-privileged.rules > /usr/local/sbin/generate_privileged_audit_sample_rules.sh",
              path: ['/usr/bin', '/usr/sbin', '/bin', '/sbin'],
              unless: [
                'test -f /usr/share/doc/audit-2.8.5/rules/.31-privileged.rules.sha512',
                'sha512sum -c --status /usr/share/doc/audit-2.8.5/rules/.31-privileged.rules.sha512',
              ],
                                                                           }).that_notifies('Exec[build_privileged_ruleset]')

            is_expected.to contain_exec('build_privileged_ruleset').with({
                                                                           command: '/bin/bash "/usr/local/sbin/generate_privileged_audit_sample_rules.sh"',
              refreshonly: true,
                                                                         })

            is_expected.to contain_file('/etc/audit/rules.d/31-privileged.rules').with({
                                                                                         ensure: 'file',
              source: 'file:///usr/share/doc/audit-2.8.5/rules/31-privileged.rules.evaluated',
                                                                                       }).that_notifies('Class[auditd::service]').that_requires('Exec[build_privileged_ruleset]')
          end
        }
      end

      context 'with additional simp profile and some built_ins' do
        let(:params) do
          {
            default_audit_profiles: [
              'built_in',
              'simp',
            ]
          }
        end

        let(:hieradata) { 'built_in_audit_profile/random_sample_rulesets' }

        # auditd::config::audit_profiles validation
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_auditd__rule('audit_auditd_config').with_content(%r{-w /var/log/audit -p wa -k audit-logs}) }

        it 'configures auditd to ignore rule failures' do
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(%r{^-i$})
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(%r{^-c$})
        end

        it 'configures buffer size' do
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
            %r{^-b\s+16384$},
          )
        end

        it 'configures failure mode' do
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
            %r{^-f\s+1$},
          )
        end

        it 'configures rate limiting' do
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
            %r{^-r\s+0$},
          )
        end

        it 'adds a drop rule to ignore anonymous and daemon events' do
          is_expected.to contain_file('/etc/audit/rules.d/05_default_drop.rules').with_content(
            %r{^-a\s+never,exit\s+-F\s+auid=-1$},
          )
        end

        it 'adds a rule to drop crond events' do
          is_expected.to contain_file('/etc/audit/rules.d/05_default_drop.rules').with_content(
            %r{^-a\s+never,user\s+-F\s+subj_type=crond_t$},
          )
        end

        it 'adds a rule to drop events from system services' do
          is_expected.to contain_file('/etc/audit/rules.d/05_default_drop.rules').with_content(
            %r{^-a\s+never,exit\s+-F\s+auid!=0\s+-F\s+auid<#{facts[:uid_min]}$},
          )
        end

        it { is_expected.to contain_class('auditd::config::audit_profiles::simp') }
        it { is_expected.to contain_class('auditd::config::audit_profiles::built_in') }

        # audit::config::audit_profiles::built_in validation
        it {
          if facts[:auditd_major_version] == '3'
            is_expected.to contain_file('/etc/audit/rules.d/10-base-config.rules').with({
                                                                                          ensure: 'file',
              source: 'file:///usr/share/audit/sample-rules/10-base-config.rules',
                                                                                        }).that_notifies('Class[auditd::service]')

            is_expected.to contain_file('/etc/audit/rules.d/10-no-audit.rules').with({
                                                                                       ensure: 'file',
              source: 'file:///usr/share/audit/sample-rules/10-no-audit.rules',
                                                                                     }).that_notifies('Class[auditd::service]')

            is_expected.to contain_file('/etc/audit/rules.d/99-finalize.rules').with({
                                                                                       ensure: 'file',
              source: 'file:///usr/share/audit/sample-rules/99-finalize.rules',
                                                                                     }).that_notifies('Class[auditd::service]')

          else
            is_expected.to contain_file('/etc/audit/rules.d/10-base-config.rules').with({
                                                                                          ensure: 'file',
              source: 'file:///usr/share/doc/audit-2.8.5/rules/10-base-config.rules',
                                                                                        }).that_notifies('Class[auditd::service]')

            is_expected.to contain_file('/etc/audit/rules.d/10-no-audit.rules').with({
                                                                                       ensure: 'file',
              source: 'file:///usr/share/doc/audit-2.8.5/rules/10-no-audit.rules',
                                                                                     }).that_notifies('Class[auditd::service]')

            is_expected.to contain_file('/etc/audit/rules.d/99-finalize.rules').with({
                                                                                       ensure: 'file',
              source: 'file:///usr/share/doc/audit-2.8.5/rules/99-finalize.rules',
                                                                                     }).that_notifies('Class[auditd::service]')
          end
          is_expected.to contain_notify('bad_sample_set not found')
        }

        # auditd::config::audit_profiles::simp validation
        it {
          expected = File.read('spec/classes/config/audit_profiles/expected/simp_el7_basic_rules.txt')
          is_expected.to contain_file('/etc/audit/rules.d/50_01_simp_base.rules').with_content(expected)
        }

        it 'specifies a key specified for each rule' do
          base_rules = catalogue.resource('File[/etc/audit/rules.d/50_01_simp_base.rules]')[:content].split("\n")

          rules_with_tags = base_rules.select { |x| x.include?(' -k ') }
          rules_with_tags.delete_if { |x| x =~ %r{ -k \S+} }

          expect(rules_with_tags).to be_empty
        end

        it 'disables chmod auditing by default' do
          # chmod is disabled by default (SIMP-2250)
          is_expected.not_to contain_file('/etc/audit/rules.d/50_01_simp_base.rules').with_content(
            %r{^-a always,exit -F arch=b\d\d -S chmod,fchmod,fchmodat -k chmod$},
          )
        end

        it 'disables rename/remove auditing by default' do
          is_expected.not_to contain_file('/etc/audit/rules.d/50_01_simp_base.rules').with_content(
            %r{^-a always,exit -F arch=b\d\d -S rename,renameat,rmdir,unlink,unlinkat -F perm=x -k delete},
          )
        end

        it 'disables umask auditing by default' do
          is_expected.not_to contain_file('/etc/audit/rules.d/50_01_simp_base.rules').with_content(
            %r{^-a always,exit -F arch=b\d\d -S umask -k umask},
          )
        end

        it 'disables package command auditing is disabled by default' do
          is_expected.not_to contain_file('/etc/audit/rules.d/50_01_simp_base.rules').with_content(
            %r{^-w /(usr/)?bin/(rpm|yum) -p x},
          )
        end

        it 'disables selinux commands auditing by default' do
          is_expected.not_to contain_file('/etc/audit/rules.d/50_01_simp_base.rules').with_content(
            %r{^-a always,exit -F path=/usr/bin/(chcon|semanage|setsebool) -F perm=x -k privileged-priv_change},
          )

          is_expected.not_to contain_file('/etc/audit/rules.d/50_01_simp_base.rules').with_content(
            %r{^-a always,exit -F path=/(usr/)?sbin/setfiles -F perm=x -k privileged-priv_change},
          )
        end
      end
    end
  end
end
