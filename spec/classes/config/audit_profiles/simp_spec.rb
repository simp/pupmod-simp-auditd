require 'spec_helper'
require_relative '../../../support/file_lines'

# We have to test auditd::config::audit_profiles::simp via auditd,
# because auditd::config::audit_profiles::simp is private.  To take
# advantage of hooks built into puppet-rspec, the class described needs
# to be the class instantiated, i.e., auditd. Then, to adjust the
# private class's parameters, we will use hieradata.
#
# The base rules file is edited rule by rule with file_line, so these specs
# replay the file_lines (see spec/support/file_lines.rb): `rules` is what a
# fresh node gets, `upgraded` is what becomes of the file 10.x wrote with the
# default toggles.
describe 'auditd' do
  include FileLines

  # Every toggle is unset by default. This config enforces simp:defaults
  # underneath each context's hieradata, so the contexts start from the
  # toggles 10.x had on by default.
  let(:hiera_config) { File.expand_path('../../../fixtures/hieradata/hiera_simp_defaults.yaml', __dir__) }

  let(:path) { '/etc/audit/rules.d/50_00_simp_base.rules' }
  let(:basic_10x) { File.read('spec/classes/config/audit_profiles/expected/simp_basic_rules.txt') }
  let(:rules) { apply_file_lines(catalogue, path) }
  let(:upgraded) { apply_file_lines(catalogue, path, basic_10x) }

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts
      end

      # The watch rules on auditd's own configuration sit behind
      # audit_auditd_config, which simp:defaults turns on too; this file
      # only tests the base rules.
      let(:base_params) do
        {
          default_audit_profiles: ['simp'],
        }
      end

      let(:params) { base_params }

      it { is_expected.to compile.with_all_deps }

      context 'with no toggle set' do
        let(:hiera_config) { File.expand_path('../../../fixtures/hieradata/hiera.yaml', __dir__) }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('auditd::config::audit_profiles::simp') }
        it { is_expected.not_to contain_file(path) }

        it 'edits no rule' do
          expect(catalogue.resources.select { |r| r.type == 'File_line' && r[:path] == path }).to be_empty
        end

        # Undeclared, the purge would delete the file.
        context 'with the purge on' do
          let(:params) { base_params.merge(purge_auditd_rules: true) }

          it { is_expected.to contain_file(path).with(ensure: 'file', content: nil) }

          it 'edits no rule' do
            expect(catalogue.resources.select { |r| r.type == 'File_line' && r[:path] == path }).to be_empty
          end
        end
      end

      context 'with only audit_chown set' do
        let(:hiera_config) { File.expand_path('../../../fixtures/hieradata/hiera.yaml', __dir__) }
        let(:hieradata) { 'simp_audit_profile/only__audit_chown' }

        it { is_expected.to contain_file(path).with(ensure: 'file', content: nil) }

        it 'writes only the chown rules' do
          expect(rules).to eq(<<~RULES)
            -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -k chown
            -a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -k chown
          RULES
        end

        it 'leaves every other rule in an existing file alone' do
          expect(upgraded).to eq(basic_10x)
        end
      end

      context 'with the simp:defaults toggles' do
        it 'writes the rules 10.x wrote, in the same order' do
          expect(rules).to eq(rules_in(basic_10x))
        end

        it 'leaves the file 10.x wrote unchanged' do
          expect(upgraded).to eq(basic_10x)
        end

        it 'converges in one run' do
          expect(file_line_changes(catalogue, path, rules)).to eq([])
          expect(file_line_changes(catalogue, path, upgraded)).to eq([])
        end

        # see $auditd::config::rule_file_attributes
        it {
          is_expected.to contain_file(path).with(
            ensure: 'file',
            content: nil,
            owner: 'root',
            group: 'root',
            mode: 'u+rwX,g-rwx,o-rwx',
          )
        }

        it 'specifies a key specified for each rule' do
          rules_without_tags = rules.lines.grep_v(%r{ (-k |-F key=)\S+$})

          expect(rules_without_tags).to be_empty
        end

        it 'disables chmod auditing by default' do
          # chmod is disabled by default (SIMP-2250)
          expect(rules).not_to match(%r{^-a always,exit -F arch=b\d\d -S chmod,fchmod,fchmodat -k chmod$})
        end

        it 'disables rename/remove auditing by default' do
          expect(rules).not_to match(%r{^-a always,exit -F arch=b\d\d -S rename,renameat,rmdir,unlink,unlinkat -F perm=x -k delete})
        end

        it 'disables umask auditing by default' do
          expect(rules).not_to match(%r{^-a always,exit -F arch=b\d\d -S umask -k umask})
        end

        it 'disables package command auditing is disabled by default' do
          expect(rules).not_to match(%r{^-w /(usr/)?bin/(rpm|yum) -p x})
        end

        it 'disables selinux commands auditing by default' do
          expect(rules).not_to match(%r{^-a always,exit -F path=/usr/bin/(chcon|semanage|setsebool) -F perm=x -k privileged-priv_change})
          expect(rules).not_to match(%r{^-a always,exit -F path=/(usr/)?sbin/setfiles -F perm=x -k privileged-priv_change})
        end

        context 'on a host without grub' do
          let(:facts) { super().merge(grub_version: nil) }

          it 'disables auditing of grub' do
            expect(rules).not_to match(%r{^-w /boot/grub/grub.conf})
            expect(rules).not_to match(%r{^-w /etc/grub.d})
          end
        end
      end

      context 'with root audit level set to aggressive' do
        let(:params) { base_params.merge(root_audit_level: 'aggressive') }
        let(:aggressive_10x) { File.read('spec/classes/config/audit_profiles/expected/simp_aggressive_rules.txt') }

        it { expect(rules).to eq(rules_in(aggressive_10x)) }

        it 'replaces the su-root rules in place' do
          expect(upgraded).to eq(aggressive_10x)
        end
      end

      context 'with root audit level set to insane' do
        let(:params) { base_params.merge(root_audit_level: 'insane') }
        let(:insane_10x) { File.read('spec/classes/config/audit_profiles/expected/simp_insane_rules.txt') }

        it { expect(rules).to eq(rules_in(insane_10x)) }

        it 'replaces the su-root rules in place' do
          expect(upgraded).to eq(insane_10x)
        end
      end

      context 'with an audit_auditd_cmds_list entry set to absent' do
        let(:hieradata) { 'simp_audit_profile/absent__audit_auditd_cmds_list_entry' }

        it { expect(rules).not_to include('-w /usr/sbin/auvirt -p x') }

        it 'removes only that rule from an existing file' do
          expect(upgraded).to eq(basic_10x.sub("-w /usr/sbin/auvirt -p x -k access-audit-trail\n", ''))
        end
      end

      context 'with a root audit syscall set to absent' do
        let(:hieradata) { 'simp_audit_profile/absent__basic_root_audit_syscall' }

        it 'drops it from the su-root rules in place' do
          expect(upgraded).to eq(basic_10x.gsub(',swapoff,swapon -k su-root-activity', ',swapoff -k su-root-activity'))
        end
      end

      # A toggle turned on later is appended to the end of an existing file,
      # not put back where a fresh file would have it (see the README).
      context 'with chmod auditing enabled on an existing file' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_chmod' }

        it 'appends the chmod rules' do
          expect(upgraded).to eq(basic_10x + <<~RULES)
            -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k chmod
            -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -k chmod
          RULES
        end
      end

      # check disabling of parameters for which the key is unique
      { 'access'                      => 'disable__audit_unsuccessful_file_operations',
        'chown'                       => 'disable__audit_chown',
        'attr'                        => 'disable__audit_attr',
        'su-root-activity'            => 'disable__audit_su_root_activity',
        'suid-exec'                   => 'disable__audit_suid_sgid',
        'modules'                     => 'disable__audit_kernel_modules',
        'audit_time_rules'            => 'disable__audit_time',
        'audit_network_modifications' => 'disable__audit_locale',
        'mount'                       => 'disable__audit_mount',
        'audit_account_changes'       => 'disable__audit_local_account',
        'MAC-policy'                  => 'disable__audit_selinux_policy',
        'logins'                      => 'disable__audit_login_files',
        'session'                     => 'disable__audit_session_files',
        'CFG_grub'                    => 'disable__audit_cfg_grub',
        'CFG_cron'                    => 'disable__audit_cfg_cron',
        'CFG_shell'                   => 'disable__audit_cfg_shell',
        'CFG_pam'                     => 'disable__audit_cfg_pam',
        'CFG_security'                => 'disable__audit_cfg_security',
        'CFG_services'                => 'disable__audit_cfg_services',
        'CFG_xinetd'                  => 'disable__audit_cfg_xinetd',
        'yum-config'                  => 'disable__audit_cfg_yum',
        'privileged-passwd'           => 'disable__audit_passwd_cmds',
        'privileged-postfix'          => 'disable__audit_postfix_cmds',
        'privileged-ssh'              => 'disable__audit_ssh_keysign_cmd',
        'privileged-cron'             => 'disable__audit_crontab_cmd',
        'privileged-pam'              => 'disable__audit_pam_timestamp_check_cmd', }.each do |key, hiera_file|
        context "with #{key} auditing disabled" do
          let(:hieradata) { "simp_audit_profile/#{hiera_file}" }

          it { expect(rules).not_to match(%r{^.* -k #{key}$}) }

          it 'removes the rules from an existing file' do
            expect(basic_10x).to match(%r{^.* -k #{key}$})
            expect(upgraded).not_to match(%r{^.* -k #{key}$})
          end
        end
      end

      context 'with privilege-related command auditing disabled' do
        let(:hieradata) { 'simp_audit_profile/disable__audit_priv_cmds' }

        [
          %r{^-a always,exit -F path=/(usr/)?bin/su -F perm=x -k privileged-priv_change$},
          %r{^-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged-priv_change$},
          %r{^-a always,exit -F path=/usr/bin/newgrp -F perm=x -k privileged-priv_change$},
          %r{^-a always,exit -F path=/usr/bin/chsh -F perm=x -k privileged-priv_change$},
          %r{^-a always,exit -F path=/(usr/)?bin/sudoedit -F perm=x -k privileged-priv_change$},
        ].each do |command_regex|
          it { expect(rules).not_to match(command_regex) }
          it { expect(upgraded).not_to match(command_regex) }
        end
      end

      context 'with sudoers config auditing disabled' do
        let(:hieradata) { 'simp_audit_profile/disable__audit_cfg_sudoers' }

        [
          %r{^-w /etc/sudoers -p wa -k CFG_sys$},
          %r{^-w /etc/sudoers.d/ -p wa -k CFG_sys$},
        ].each do |command_regex|
          it { expect(rules).not_to match(command_regex) }
          it { expect(upgraded).not_to match(command_regex) }
        end
      end

      context 'with other system config auditing disabled' do
        let(:hieradata) { 'simp_audit_profile/disable__audit_cfg_sys' }

        [
          %r{^-w /etc/default -p wa -k CFG_sys$},
          %r{^-w /etc/exports -p wa -k CFG_sys$},
          %r{^-w /etc/fstab -p wa -k CFG_sys$},
          %r{^-w /etc/host.conf -p wa -k CFG_sys$},
          %r{^-w /etc/hosts.allow -p wa -k CFG_sys$},
          %r{^-w /etc/hosts.deny -p wa -k CFG_sys$},
          %r{^-w /etc/initlog.conf -p wa -k CFG_sys$},
          %r{^-w /etc/inittab -p wa -k CFG_sys$},
          %r{^-w /etc/issue -p wa -k CFG_sys$},
          %r{^-w /etc/issue.net -p wa -k CFG_sys$},
          %r{^-w /etc/krb5.conf -p wa -k CFG_sys$},
          %r{^-w /etc/ld.so.conf -p wa -k CFG_sys$},
          %r{^-w /etc/ld.so.conf.d -p wa -k CFG_sys$},
          %r{^-w /etc/login.defs -p wa -k CFG_sys$},
          %r{^-w /etc/modprobe.conf.d -p wa -k CFG_sys$},
          %r{^-w /etc/modprobe.d/00_simp_blacklist.conf -p wa -k CFG_sys$},
          %r{^-w /etc/nsswitch.conf -p wa -k CFG_sys$},
          %r{^-w /etc/aliases -p wa -k CFG_sys$},
          %r{^-w /etc/at.deny -p wa -k CFG_sys$},
          %r{^-w /etc/rc.d/init.d -p wa -k CFG_sys$},
          %r{^-w /etc/rc.local -p wa -k CFG_sys$},
          %r{^-w /etc/rc.sysinit -p wa -k CFG_sys$},
          %r{^-w /etc/resolv.conf -p wa -k CFG_sys$},
          %r{^-w /etc/securetty -p wa -k CFG_sys$},
          %r{^-w /etc/snmp/snmpd.conf -p wa -k CFG_sys$},
          %r{^-w /etc/ssh/sshd_config -p wa -k CFG_sys$},
          %r{^-w /etc/sysconfig -p wa -k CFG_sys$},
          %r{^-w /etc/sysctl.conf -p wa -k CFG_sys$},
          %r{^-w /lib/firmware/microcode.dat -p wa -k CFG_sys$},
          %r{^-w /var/spool/at -p wa -k CFG_sys$},
        ].each do |command_regex|
          it { expect(rules).not_to match(command_regex) }
          it { expect(upgraded).not_to match(command_regex) }
        end

        # audit_cfg_sudoers shares the CFG_sys tag; only the matched rules go.
        it { expect(upgraded).to match(%r{^-w /etc/sudoers -p wa -k CFG_sys$}) }
      end

      context 'with ptrace auditing disabled' do
        let(:hieradata) { 'simp_audit_profile/disable__audit_ptrace' }

        it { expect(rules).not_to match(%r{^-a always,exit -F arch=b\d\d -S ptrace}) }
        it { expect(upgraded).not_to match(%r{^-a always,exit -F arch=b\d\d -S ptrace}) }
      end

      context 'with personality auditing disabled' do
        let(:hieradata) { 'simp_audit_profile/disable__audit_personality' }

        it { expect(rules).not_to match(%r{^-a always,exit -F arch=b\d\d -S personality -k paranoid$}) }
        it { expect(upgraded).not_to match(%r{^-a always,exit -F arch=b\d\d -S personality -k paranoid$}) }

        # audit_ptrace shares the paranoid tag.
        it { expect(upgraded).to match(%r{^-a always,exit -F arch=b\d\d -S ptrace -k paranoid$}) }
      end

      context 'with chmod auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_chmod' }

        it { expect(rules).to match(%r{^-a always,exit -F arch=b\d\d -S chmod,fchmod,fchmodat -k chmod$}) }
      end

      context 'with rename/remove operation auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_rename_remove' }

        it { expect(rules).to match(%r{^-a always,exit -F arch=b64 -S rename,renameat,rmdir,unlink,unlinkat -F perm=x -k delete}) }
        it { expect(rules).to match(%r{^-a always,exit -F arch=b32 -S rename,renameat,rmdir,unlink,unlinkat -F perm=x -k delete}) }
      end

      context 'with umask operations auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_umask' }

        it { expect(rules).to match(%r{^-a always,exit -F arch=b\d\d -S umask -k umask}) }
      end

      context 'with selinux command auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_selinux_cmds' }

        it { expect(rules).to match(%r{^-a always,exit -F path=/usr/bin/chcon -F perm=x -k privileged-priv_change}) }
        it { expect(rules).to match(%r{^-a always,exit -F path=/usr/sbin/semanage -F perm=x -k privileged-priv_change}) }
        it { expect(rules).to match(%r{^-a always,exit -F path=/usr/sbin/setsebool -F perm=x -k privileged-priv_change}) }
        it { expect(rules).to match(%r{^-a always,exit -F path=/(usr/)?sbin/setfiles -F perm=x -k privileged-priv_change}) }
      end

      context 'with yum command auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_yum_cmd' }

        it { expect(rules).to match(%r{^-w /(usr/)?bin/yum -p x}) }
      end

      context 'with rpm command auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_rpm_cmd' }

        it { expect(rules).to match(%r{^-w /(usr/)?bin/rpm -p x}) }
      end

      context 'with all auditing options enabled and custom tags' do
        let(:hieradata) { 'simp_audit_profile/enable_all_custom_tags' }
        let(:params) { base_params.merge(root_audit_level: 'insane') }
        let(:custom_10x) { File.read('spec/classes/config/audit_profiles/expected/simp_all_rules_custom_tags.txt') }

        it 'converges in one run' do
          expect(file_line_changes(catalogue, path, rules)).to eq([])
          expect(file_line_changes(catalogue, path, upgraded)).to eq([])
        end

        it 'uses custom tags as rule keys' do
          expect(rules).to eq(rules_in(custom_10x))
        end

        # A changed tag replaces each rule in place, so the rules keep their
        # order. The toggles this hieradata turns on are appended after them.
        it 'replaces the tags in an existing file in place' do
          body = ->(l) { l.sub(%r{ (-k |-F key=)\S+$}, '').sub(%r{ -S \S+}, ' -S *') }
          old = rules_in(basic_10x).lines
          new = apply_file_lines(catalogue, path, rules_in(basic_10x)).lines

          expect(new.first(old.size).map(&body)).to eq(old.map(&body))
          expect(new.sort).to eq(rules_in(custom_10x).lines.sort)
        end

        # The hieradata overrides every non-deprecated *_tag parameter with a
        # 'my_'-prefixed value, so any key rendered without that prefix is a
        # default hardcoded into the manifest rather than read from a
        # parameter.
        it 'reads every rule key from a tag parameter' do
          keys = rules.scan(%r{(?:-k |-F key=)(\S+)}).flatten.uniq

          expect(keys).not_to be_empty
          expect(keys.grep_v(%r{\Amy_})).to eq([])
        end
      end

      context 'with multiple audit profiles' do
        let(:params) { base_params.merge(default_audit_profiles: ['simp', 'stig']) }

        it { expect(rules).to eq(rules_in(basic_10x)) }
        it { is_expected.to contain_file('/etc/audit/rules.d/50_01_stig_base.rules') }
      end

      context 'with auditd version' do
        # EL9. This replaced a 2.6.5 context: init.pp takes the same branch for
        # anything at or above 2.6.0, so the coverage is identical and the fact
        # now names a release we actually support.
        context '3.1.5' do
          let(:facts) do
            new_facts = Marshal.load(Marshal.dump(os_facts))
            new_facts[:auditd_version] = '3.1.5'

            new_facts
          end

          # auditd.conf is edited key by key with ini_setting, so assert the
          # managed keys rather than the contents of a rendered file.
          # write_logs derives from log_format when it has not been given a
          # value of its own, so each context sets both explicitly.
          context 'default options' do
            let(:params) { base_params.merge(log_format: 'raw', write_logs: true) }

            it { is_expected.to contain_ini_setting('auditd.conf log_format').with_value('raw') }
            it { is_expected.to contain_ini_setting('auditd.conf write_logs').with_value('yes') }
          end

          context 'write_logs = false' do
            let(:params) { base_params.merge(log_format: 'raw', write_logs: false) }

            it { is_expected.to contain_ini_setting('auditd.conf log_format').with_value('raw') }
            it { is_expected.to contain_ini_setting('auditd.conf write_logs').with_value('no') }
          end

          context 'log_format = ENRICHED' do
            let(:params) { base_params.merge(log_format: 'ENRICHED', write_logs: true) }

            it { is_expected.to contain_ini_setting('auditd.conf log_format').with_value('ENRICHED') }
            it { is_expected.to contain_ini_setting('auditd.conf write_logs').with_value('yes') }
          end
        end
      end

      context 'with deprecated parameters' do
        context 'disable audit_cfg_sudoers using deprecated audit_sudoers' do
          let(:hieradata) { 'simp_audit_profile/disable__audit_sudoers' }

          [
            %r{^-w /etc/sudoers -p wa -k CFG_sys$},
            %r{^-w /etc/sudoers.d/ -p wa -k CFG_sys$},
          ].each do |command_regex|
            it do
              if Puppet[:strict] == :error
                is_expected.to compile.and_raise_error(%r{'auditd::config::audit_profiles::simp::audit_sudoers' is deprecated\.})
              else
                expect(rules).not_to match(command_regex)
              end
            end
          end
        end

        context 'set audit_cfg_sudoers rule key using deprecated audit_sudoers_tag' do
          let(:hieradata) { 'simp_audit_profile/set__audit_sudoers_tag' }

          [
            %r{^-w /etc/sudoers -p wa -k old_sudoers_tag$},
            %r{^-w /etc/sudoers.d/ -p wa -k old_sudoers_tag$},
          ].each do |command_regex|
            it do
              if Puppet[:strict] == :error
                is_expected.to compile.and_raise_error(%r{'auditd::config::audit_profiles::simp::audit_sudoers_tag' is deprecated\.})
              else
                expect(rules).to match(command_regex)
              end
            end
          end

          [
            %r{^-w /etc/sudoers -p wa -k CFG_sys$},
            %r{^-w /etc/sudoers.d/ -p wa -k CFG_sys$},
          ].each do |command_regex|
            it do
              if Puppet[:strict] == :error
                is_expected.to compile.and_raise_error(%r{'auditd::config::audit_profiles::simp::audit_sudoers_tag' is deprecated\.})
              else
                expect(rules).not_to match(command_regex)
              end
            end
          end
        end

        context 'disable audit_cfg_grub using deprecated audit_grub' do
          let(:hieradata) { 'simp_audit_profile/disable__audit_grub' }

          it do
            if Puppet[:strict] == :error
              is_expected.to compile.and_raise_error(%r{'auditd::config::audit_profiles::simp::audit_grub' is deprecated\.})
            else
              expect(rules).not_to match(%r{^.* -k CFG_grub$})
            end
          end
        end

        context 'set audit_cfg_grub rule key using deprecated audit_grub_tag' do
          let(:hieradata) { 'simp_audit_profile/set__audit_grub_tag' }

          it do
            if Puppet[:strict] == :error
              is_expected.to compile.and_raise_error(%r{'auditd::config::audit_profiles::simp::audit_grub_tag' is deprecated\.})
            else
              expect(rules).to match(%r{^.*grub.(d|conf).* -k old_grub_tag$})
              expect(rules).not_to match(%r{^.* -k CFG_grub$})
            end
          end
        end

        context 'disable audit_cfg_yum using deprecated audit_yum' do
          let(:hieradata) { 'simp_audit_profile/disable__audit_yum' }

          it do
            if Puppet[:strict] == :error
              is_expected.to compile.and_raise_error(%r{'auditd::config::audit_profiles::simp::audit_yum' is deprecated\.})
            else
              expect(rules).not_to match(%r{^.* -k yum-config$})
            end
          end
        end

        context 'set audit_cfg_yum rule key using deprecated audit_yum_tag' do
          let(:hieradata) { 'simp_audit_profile/set__audit_yum_tag' }

          it do
            if Puppet[:strict] == :error
              is_expected.to compile.and_raise_error(%r{'auditd::config::audit_profiles::simp::audit_yum_tag' is deprecated\.})
            else
              expect(rules).to match(%r{^.*/etc/yum.* -k old_yum_tag$})
              expect(rules).not_to match(%r{^.* -k yum-config$})
            end
          end
        end
      end
    end
  end
end
