require 'spec_helper'

# We have to test auditd::config via auditd, because auditd::config is
# private.  To take advantage of hooks built into puppet-rspec, the
# class described needs to be the class instantiated, i.e., auditd.
# This test also includes tests for private class auditd::config::logging

describe 'auditd' do
  # Every file this module declares in /etc/audit/rules.d with the simp
  # profile; see $auditd::config::rule_file_attributes for why these
  # must carry owner/group/mode themselves.
  RULES_D_FILES = [
    '/etc/audit/rules.d/00_head.rules',
    '/etc/audit/rules.d/05_default_drop.rules',
    '/etc/audit/rules.d/99_tail.rules',
    '/etc/audit/rules.d/50_00_simp_base.rules',
  ].freeze

  # Written only when audit_auditd_config asks for it. It used to default to
  # true; the simp:defaults profile is what turns it back on now (plan D3).
  AUDITD_CONFIG_RULES = '/etc/audit/rules.d/75.audit_auditd_config.rules'.freeze

  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) { os_facts }

        # The blast-radius contract at the config layer.
        #
        # auditd::config is always evaluated -- it is included unconditionally
        # by the auditd class -- so "does nothing" has to be asserted about the
        # resources it declares, not about whether it runs.
        context 'with default parameters' do
          let(:params) { {} }

          it { is_expected.to compile.with_all_deps }

          # The /etc/audit purge is gone for good. It deleted files the audit
          # package itself ships, which is what made a bare include dangerous.
          it { is_expected.not_to contain_file('/etc/audit') }

          # rules.d is only declared when it has work to do: purging files this
          # module does not manage, or setting attributes on ones it writes.
          it { is_expected.not_to contain_file('/etc/audit/rules.d') }

          # augenrules owns these. Unmanaged unless audit_rules_* asks.
          it { is_expected.not_to contain_file('/etc/audit/audit.rules') }
          it { is_expected.not_to contain_file('/etc/audit/audit.rules.prev') }

          # Declared only to enforce a non-default group on the config.
          it { is_expected.not_to contain_file('/etc/audit/auditd.conf') }

          it { is_expected.not_to contain_file('/var/log/audit') }
          it { is_expected.not_to contain_file('/etc/audit/plugins.d') }

          # The package's own preamble stays. Nothing here has an opinion to
          # put in its place.
          it { is_expected.not_to contain_file('/etc/audit/rules.d/audit.rules') }

          it { is_expected.not_to contain_class('auditd::config::audit_profiles') }
          it { is_expected.not_to contain_class('auditd::config::audit_profiles::simp') }
          it { is_expected.not_to contain_class('auditd::config::logging') }
          it { is_expected.not_to contain_class('auditd::config::audisp') }
          it { is_expected.not_to contain_class('auditd::config::audisp::syslog') }
          it { is_expected.not_to contain_augeas('auditd/USE_AUGENRULES') }

          # Not one key of auditd.conf is rewritten. Whatever the package
          # shipped stays exactly as it is.
          it 'writes no auditd.conf settings' do
            settings = catalogue.resources.select { |r| r.type == 'Ini_setting' }.map(&:title)
            expect(settings).to be_empty
          end
        end # Default params

        context 'with audit_rules_* parameters set' do
          let(:params) do
            {
              audit_rules_owner: 'root',
              audit_rules_group: 'root',
              audit_rules_mode: '0600',
            }
          end

          it { is_expected.to compile.with_all_deps }
          ['/etc/audit/audit.rules', '/etc/audit/audit.rules.prev'].each do |f|
            it {
              is_expected.to contain_file(f).with(
                owner: 'root',
                group: 'root',
                mode: '0600',
              )
            }
          end
        end

        # Each audit_rules_* attribute is independent; setting one must not
        # invent values for the others and start fighting augenrules over them.
        context 'with only audit_rules_mode set' do
          let(:params) { { audit_rules_mode: '0600' } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_file('/etc/audit/audit.rules').with_mode('0600').without_owner.without_group }
        end

        # Purging claims rules.d, so the rule files a site drops in (via
        # auditd::rule) need the module's preamble: the package's was just
        # purged. The default drop rules are profile content and stay out.
        context 'with purge_auditd_rules => true' do
          let(:params) { { purge_auditd_rules: true } }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/etc/audit/rules.d').with(
              ensure: 'directory',
              owner: 'root',
              group: 'root',
              mode: 'u+rwX,g-rwx,o-rwx',
              recurse: true,
              purge: true,
              force: true,
            )
          }

          it { is_expected.to contain_class('auditd::config::audit_profiles') }
          it { is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(%r{^-b 16384$}) }
          it { is_expected.to contain_file('/etc/audit/rules.d/99_tail.rules') }
          it { is_expected.not_to contain_file('/etc/audit/rules.d/05_default_drop.rules') }
          it { is_expected.not_to contain_file('/etc/audit/rules.d/50_00_simp_base.rules') }
          it { is_expected.to contain_file('/etc/audit/rules.d/audit.rules').with_ensure('absent') }
        end

        # A profile writes rule files, so rules.d gets declared to carry their
        # group and mode -- but purging stays off unless it was asked for.
        context 'with a profile but no purge' do
          let(:params) { { default_audit_profiles: ['simp'] } }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/etc/audit/rules.d').with(
              ensure: 'directory',
              owner: 'root',
              group: 'root',
              mode: 'u+rwX,g-rwx,o-rwx',
              recurse: false,
              purge: false,
              force: false,
            )
          }

          RULES_D_FILES.each do |f|
            it {
              is_expected.to contain_file(f).with(
                owner: 'root',
                group: 'root',
                mode: 'u+rwX,g-rwx,o-rwx',
              )
            }
          end

          # The watch rules on auditd's own configuration are content, not
          # plumbing: selecting a profile no longer drags them in.
          it { is_expected.not_to contain_file(AUDITD_CONFIG_RULES) }
          it { is_expected.not_to contain_auditd__rule('audit_auditd_config') }

          # The packaged rules.d/audit.rules sorts after 00_head.rules and
          # augenrules lets the later file win on a duplicated -b/-f, so
          # without a purge it has to be removed explicitly or the values
          # written above never take effect.
          it { is_expected.to contain_file('/etc/audit/rules.d/audit.rules').with_ensure('absent') }
        end

        context 'with a profile and audit_auditd_config => true' do
          let(:params) { { default_audit_profiles: ['simp'], audit_auditd_config: true } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_auditd__rule('audit_auditd_config') }
          it {
            is_expected.to contain_file(AUDITD_CONFIG_RULES).with(
              owner: 'root',
              group: 'root',
              mode: 'u+rwX,g-rwx,o-rwx',
            )
          }
        end

        # audit_auditd_config only ever acted from inside audit_profiles, so
        # without a profile it has nothing to write no matter what it is set to.
        context 'with audit_auditd_config => true but no profile' do
          let(:params) { { audit_auditd_config: true } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.not_to contain_file(AUDITD_CONFIG_RULES) }
        end

        # custom_spec.rb drives auditd::config::audit_profiles::custom through a
        # stubbed auditd::config, so it can only prove the splat is wired -- it
        # cannot catch a regression in the real $rule_file_attributes. Exercise
        # the custom profile through the real class here so the actual
        # owner/group/mode are pinned.
        context "with default_audit_profiles ['custom']" do
          let(:params) { { default_audit_profiles: ['custom'] } }
          let(:hieradata) { 'custom_audit_profile/rules' }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/etc/audit/rules.d/50_00_custom_base.rules').with(
              owner: 'root',
              group: 'root',
              mode: 'u+rwX,g-rwx,o-rwx',
            )
          }

          context 'with a non-root config_group' do
            let(:params) { { default_audit_profiles: ['custom'], config_group: 'rspec' } }

            it {
              is_expected.to contain_file('/etc/audit/rules.d/50_00_custom_base.rules').with(
                owner: 'root',
                group: 'rspec',
                mode: 'u+rwX,g+rX,g-w,o-rwx',
              )
            }
          end
        end

        context 'with empty default_audit_profiles' do
          let(:params) { { default_audit_profiles: [] } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.not_to contain_class('auditd::config::audit_profiles') }
        end

        # The package ships and owns the default plugin directory, so this is
        # declared only when a site moves it. auditd::config::audisp::syslog
        # writes syslog.conf into whatever plugin_dir resolves to, and a
        # relocated directory nothing creates is a File with no parent.
        context 'with plugin_dir unset' do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.not_to contain_file('/etc/audit/plugins.d') }
        end

        context 'with plugin_dir set' do
          let(:params) { { plugin_dir: '/opt/audit/plugins.d' } }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/opt/audit/plugins.d').with(
              ensure: 'directory',
              owner: 'root',
              group: 'root',
              mode: 'u+rwX,g-rwx,o-rwx',
            )
          }
        end

        context 'with plugin_dir and config_group set' do
          let(:params) { { plugin_dir: '/opt/audit/plugins.d', config_group: 'rspec' } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_file('/opt/audit/plugins.d').with_group('rspec') }
        end

        # An empty string is truthy in Puppet and would reach the File
        # resources as group => ''. String[1] rejects it at the parameter.
        context 'with an empty config_group' do
          let(:params) { { config_group: '' } }

          it { is_expected.to compile.and_raise_error(%r{'config_group' expects a value of type Undef or String\[1\]}) }
        end

        context 'with an empty log_group' do
          let(:params) { { log_group: '' } }

          it { is_expected.to compile.and_raise_error(%r{'log_group' expects a value of type Undef or String\[1\]}) }
        end

        context 'with different log_group' do
          let(:params) { { log_group: 'rspec', default_audit_profiles: ['simp'] } }

          it { is_expected.to compile.with_all_deps }

          # log_group no longer drags config_group along with it. The two
          # answer different questions -- who may read the audit logs, versus
          # who may read the audit configuration -- and widening one is not a
          # request to widen the other. Concretely: a site naming its log
          # shipper's group here is not asking to show that group which
          # syscalls are and are not being watched, and CIS 6.3.4.7 wants the
          # rule files group-owned by root specifically.
          #
          # These assertions are the tripwire for that decision. If the
          # parameters are ever chained again, the group here becomes 'rspec'
          # and they fail.
          it {
            is_expected.to contain_file('/etc/audit/rules.d').with(
              ensure: 'directory',
              owner: 'root',
              group: 'root',
              mode: 'u+rwX,g-rwx,o-rwx',
            )
          }

          RULES_D_FILES.each do |f|
            it {
              is_expected.to contain_file(f).with(
                owner: 'root',
                group: 'root',
                mode: 'u+rwX,g-rwx,o-rwx',
              )
            }
          end

          # Declared only when config_group is set, which it is not here. The
          # package already ships this file root:root 0640.
          it { is_expected.not_to contain_file('/etc/audit/auditd.conf') }

          it {
            is_expected.to contain_file('/var/log/audit').with(
              ensure: 'directory',
              owner: 'root',
              group: 'rspec',
              mode: 'u+rX,g+rX,g-w,o-rwx',
              recurse: true,
            )
          }

          # The /etc/audit purge is gone, so a group change no longer drags a
          # recursive purge along with it.
          it { is_expected.not_to contain_file('/etc/audit') }
        end

        context 'with different config_group' do
          let(:params) { { config_group: 'rspec', default_audit_profiles: ['simp'] } }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/etc/audit/rules.d').with(
              ensure: 'directory',
              owner: 'root',
              group: 'rspec',
              mode: 'u+rwX,g+rX,g-w,o-rwx',
            )
          }

          RULES_D_FILES.each do |f|
            it {
              is_expected.to contain_file(f).with(
                owner: 'root',
                group: 'rspec',
                mode: 'u+rwX,g+rX,g-w,o-rwx',
              )
            }
          end

          it {
            is_expected.to contain_file('/etc/audit/auditd.conf').with(
              owner: 'root',
              group: 'rspec',
              mode: 'u+rwX,g+rX,g-w,o-rwx',
            )
          }

          # config_group governs the configuration only; the logs are
          # log_group's business and it was not set.
          it { is_expected.not_to contain_file('/var/log/audit') }
        end

        context 'with deprecated parameters' do
          context 'with default_audit_profile = true' do
            let(:params) { { default_audit_profile: true } }

            it do
              if Puppet[:strict] == :error
                is_expected.to compile.and_raise_error(%r{'auditd::default_audit_profile' is deprecated\.})
              else
                is_expected.to contain_class('auditd::config::audit_profiles')
                is_expected.to contain_class('auditd::config::audit_profiles::simp')
              end
            end
          end

          context 'with default_audit_profile = false' do
            let(:params) { { default_audit_profile: false } }

            it do
              if Puppet[:strict] == :error
                is_expected.to compile.and_raise_error(%r{'auditd::default_audit_profile' is deprecated\.})
              else
                is_expected.to compile.with_all_deps
                is_expected.not_to contain_class('auditd::config::audit_profiles')
                is_expected.not_to contain_class('auditd::config::audit_profiles::simp')
              end
            end
          end

          context "with default_audit_profile = 'simp'" do
            let(:params) { { default_audit_profile: 'simp' } }

            it do
              if Puppet[:strict] == :error
                is_expected.to compile.and_raise_error(%r{'auditd::default_audit_profile' is deprecated\.})
              else
                is_expected.to contain_class('auditd::config::audit_profiles')
                is_expected.to contain_class('auditd::config::audit_profiles::simp')
              end
            end
          end
        end

        context "with default_audit_profiles = 'built_in'" do
          let(:params) { { default_audit_profiles: ['built_in'] } }

          it { is_expected.to contain_class('auditd::config::audit_profiles') }
          it { is_expected.to contain_class('auditd::config::audit_profiles::built_in') }
        end

        # Both auditd major versions are exercised on every OS because the
        # facts are not generated for every supported release. Neither fact is
        # available if auditing in the kernel is not enabled, so the unknown
        # case is covered too.
        [
          { auditd_version: '3.0', auditd_major_version: '3' },
          { auditd_version: '2.4.5', auditd_major_version: '2' },
          { auditd_version: nil, auditd_major_version: nil },
        ].each do |more_facts|
          context "with auditd version #{more_facts[:auditd_major_version].inspect}" do
            let(:facts) do
              f = Marshal.load(Marshal.dump(os_facts))
              f[:auditd_version] = more_facts[:auditd_version]
              f[:auditd_major_version] = more_facts[:auditd_major_version]
              f
            end

            # Every auditd.conf key this module can write, asked for explicitly.
            #
            # None of these is a default any more. Before this refactor the same
            # values arrived through data/os/*.yaml and the class defaults, so a
            # bare include rewrote all of them; now the spec has to opt in to
            # each one, which is precisely the change being tested.
            #
            # space_left is no longer derived from admin_space_left, and
            # setting admin_space_left without it now fails the catalogue on
            # purpose, so this asks for both. 80 is what
            # auditd::calculate_space_left(50) returns -- the value previous
            # releases wrote here.
            let(:auditd_conf_params) do
              {
                log_file: '/var/log/audit/audit.log',
                log_format: 'raw',
                log_group: 'root',
                priority_boost: 4,
                flush: 'incremental',
                freq: 20,
                num_logs: 5,
                name_format: 'USER',
                max_log_file: 24,
                max_log_file_action: 'rotate',
                space_left_action: 'syslog',
                admin_space_left: 50,
                space_left: 80,
                admin_space_left_action: 'rotate',
                disk_full_action: 'rotate',
                disk_error_action: 'syslog',
                write_logs: true,
                local_events: true,
                verify_email: true,
                overflow_action: 'SYSLOG',
                q_depth: 160,
                max_restarts: 10,
                plugin_dir: '/etc/audit/plugins.d',
                action_mail_acct: 'root',
              }
            end

            let(:expected_settings) do
              settings = {
                'log_file' => '/var/log/audit/audit.log',
                'log_format' => 'raw',
                'log_group' => 'root',
                'priority_boost' => 4,
                'flush' => 'incremental',
                'freq' => 20,
                'num_logs' => 5,
                'name_format' => 'USER',
                'name' => facts[:networking][:fqdn],
                'max_log_file' => 24,
                'max_log_file_action' => 'rotate',
                'space_left' => 80,
                'space_left_action' => 'syslog',
                'admin_space_left' => 50,
                'admin_space_left_action' => 'rotate',
                'disk_full_action' => 'rotate',
                'disk_error_action' => 'syslog',
                'write_logs' => 'yes',
                'local_events' => 'yes',
                'verify_email' => 'yes',
                'overflow_action' => 'SYSLOG',
                'q_depth' => 160,
                'max_restarts' => 10,
                'plugin_dir' => '/etc/audit/plugins.d',
                'action_mail_acct' => 'root',
              }

              # auditd < 2.5.2 has no write_logs keyword, so $auditd::_write_logs
              # is left unset and the key is not managed at all.
              settings.delete('write_logs') if more_facts[:auditd_major_version] == '2'

              settings
            end

            context 'with every auditd.conf key set' do
              # config_group is what declares the auditd.conf File resource at
              # all -- it is an attribute parameter, not an auditd.conf key,
              # so it is merged in here rather than added to
              # auditd_conf_params. It used to arrive free by chaining off
              # log_group; that chain is gone, and without config_group there
              # is no File resource to make the no-content assertions against.
              let(:params) { auditd_conf_params.merge(config_group: 'root') }

              it { is_expected.to compile.with_all_deps }

              # The declaration for auditd.conf exists to enforce attributes.
              # It must never manage contents, or every vendor key this module
              # has no opinion about would be lost.
              it { is_expected.to contain_file('/etc/audit/auditd.conf').with(owner: 'root', group: 'root', mode: 'u+rwX,g-rwx,o-rwx') }
              it { is_expected.to contain_file('/etc/audit/auditd.conf').without_content }
              it { is_expected.to contain_file('/etc/audit/auditd.conf').without_source }

              it {
                expected_settings.each do |setting, value|
                  is_expected.to contain_ini_setting("auditd.conf #{setting}").with(
                    path: '/etc/audit/auditd.conf',
                    section: '',
                    setting: setting,
                    value: value,
                  )
                end
              }

              # Exactly the opted-in keys, and nothing else. A new key added to
              # config.pp without a decision fails here.
              it 'writes no keys beyond the ones asked for' do
                written = catalogue.resources
                                   .select { |r| r.type == 'Ini_setting' }
                                   .map { |r| r.title.sub('auditd.conf ', '') }
                                   .sort
                expect(written).to eq(expected_settings.keys.sort)
              end

              # The keys the auditd 2.x template used to write are gone. No
              # supported OS ships an auditd old enough to want them.
              it { is_expected.not_to contain_ini_setting('auditd.conf disp_qos') }
              it { is_expected.not_to contain_ini_setting('auditd.conf dispatcher') }
            end

            # name_format and name go together or not at all: 'name' is what a
            # name_format of USER resolves to, so writing one without the other
            # leaves auditd.conf internally inconsistent.
            context 'without name_format' do
              let(:params) { auditd_conf_params.reject { |k, _v| k == :name_format } }

              it { is_expected.to compile.with_all_deps }
              it { is_expected.not_to contain_ini_setting('auditd.conf name_format') }
              it { is_expected.not_to contain_ini_setting('auditd.conf name') }
            end

            context 'with syslog enabled' do
              let(:params) { { syslog: true } }

              it { is_expected.to contain_class('auditd::config::logging').that_notifies('Class[auditd::service]') }
              # Test private class config::logging
              it {
                if facts[:auditd_version].nil? || facts[:auditd_major_version] >= '3'
                  is_expected.not_to contain_class('auditd::config::audisp')
                else
                  is_expected.to contain_class('auditd::config::audisp')
                end
              }
              # Configured even before auditd_version is known: a missing
              # fact is treated as audit 3 (see auditd::config::logging).
              it { is_expected.to contain_class('auditd::config::audisp::syslog') }
            end
          end # End auditd version context
        end # End auditd version loop
      end # End OS Context
    end # End OS loop
  end
end
