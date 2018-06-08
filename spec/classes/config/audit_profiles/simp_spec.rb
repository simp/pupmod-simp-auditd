require 'spec_helper'

# We have to test auditd::config::audit_profiles::simp via auditd,
# because auditd::config::audit_profiles::simp is private.  To take
# advantage of hooks built into puppet-rspec, the class described needs
# to be the class instantiated, i.e., auditd. Then, to adjust the
# private class's parameters, we will use hieradata.
describe 'auditd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile.with_all_deps }

      context 'with default parameters' do

        it {
          if os_facts[:os][:release][:major] == '6'
            expected = File.read('spec/classes/config/audit_profiles/expected/simp_el6_basic_rules.txt')
          else
            expected = File.read('spec/classes/config/audit_profiles/expected/simp_el7_basic_rules.txt')
          end
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(expected)
        }

        it 'specifies a key specified for each rule' do
          base_rules = catalogue.resource('File[/etc/audit/rules.d/50_base.rules]')[:content].split("\n")

          rules_with_tags = base_rules.select{|x| x =~ / -k / }
          rules_with_tags.delete_if{|x| x =~ / -k \S+/}

          expect(rules_with_tags).to be_empty
        end

        it 'disables chmod auditing by default' do
          # chmod is disabled by default (SIMP-2250)
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F arch=b\d\d( -S \w*chmod\w*?)+ -k chmod$)
          )
        end

        it 'disables rename/remove auditing by default' do
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F arch=b\d\d -S rename -S renameat -S rmdir -S unlink -S unlinkat -F perm=x -k delete)
          )
        end

        it 'disables umask auditing by default' do
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F arch=b\d\d -S umask -k umask)
          )
        end

        it 'disables package command auditing is disabled by default' do
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r{^-w /(usr/)?bin/(rpm|yum) -p x}
          )

        end

        it 'disables selinux commands auditing by default' do
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r{^-a always,exit -F path=/usr/bin/(chcon|semanage|setsebool) -F perm=x -k privileged-priv_change}
          )

          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F path=/(usr/)?sbin/setfiles -F perm=x -k privileged-priv_change)
          )
        end
      end

      context 'with root audit level set to aggressive' do
        let(:params) {{ :root_audit_level => 'aggressive' }}

        it {
          if os_facts[:os][:release][:major] == '6'
            expected = File.read('spec/classes/config/audit_profiles/expected/simp_el6_aggressive_rules.txt')
          else
            expected = File.read('spec/classes/config/audit_profiles/expected/simp_el7_aggressive_rules.txt')
          end
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(expected)
        }
      end

      context 'with root audit level set to insane' do
        let(:params) {{ :root_audit_level => 'insane' }}

        it {
          if os_facts[:os][:release][:major] == '6'
            expected = File.read('spec/classes/config/audit_profiles/expected/simp_el6_insane_rules.txt')
          else
            expected = File.read('spec/classes/config/audit_profiles/expected/simp_el7_insane_rules.txt')
          end
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(expected)
        }
      end

      # check disabling of parameters for which the key is unique
      { 'access'                      => 'simp_audit_profile/disable__audit_unsuccessful_file_operations',
        'chown'                       => 'simp_audit_profile/disable__audit_chown',
        'attr'                        => 'simp_audit_profile/disable__audit_attr',
        'su-root-activity'            => 'simp_audit_profile/disable__audit_su_root_activity',
        'suid-root-exec'              => 'simp_audit_profile/disable__audit_suid_sgid',
        'modules'                     => 'simp_audit_profile/disable__audit_kernel_modules',
        'audit_time_rules'            => 'simp_audit_profile/disable__audit_time',
        'audit_network_modifications' => 'simp_audit_profile/disable__audit_locale',
        'mount'                       => 'simp_audit_profile/disable__audit_mount',
        'audit_account_changes'       => 'simp_audit_profile/disable__audit_local_account',
        'MAC-policy'                  => 'simp_audit_profile/disable__audit_selinux_policy',
        'logins'                      => 'simp_audit_profile/disable__audit_login_files',
        'session'                     => 'simp_audit_profile/disable__audit_session_files',
        'CFG_grub'                    => 'simp_audit_profile/disable__audit_cfg_grub',
        'CFG_cron'                    => 'simp_audit_profile/disable__audit_cfg_cron',
        'CFG_shell'                   => 'simp_audit_profile/disable__audit_cfg_shell',
        'CFG_pam'                     => 'simp_audit_profile/disable__audit_cfg_pam',
        'CFG_security'                => 'simp_audit_profile/disable__audit_cfg_security',
        'CFG_services'                => 'simp_audit_profile/disable__audit_cfg_services',
        'CFG_xinetd'                  => 'simp_audit_profile/disable__audit_cfg_xinetd',
        'yum-config'                  => 'simp_audit_profile/disable__audit_cfg_yum',
        'privileged-passwd'           => 'simp_audit_profile/disable__audit_passwd_cmds',
        'privileged-postfix'          => 'simp_audit_profile/disable__audit_postfix_cmds',
        'privileged-ssh'              => 'simp_audit_profile/disable__audit_ssh_keysign_cmd',
        'privileged-cron'             => 'simp_audit_profile/disable__audit_crontab_cmd',
        'privileged-pam'              => 'simp_audit_profile/disable__audit_pam_timestamp_check_cmd',
      }.each do |key, hiera_file|
        context "with #{key} auditing disabled" do
          let(:hieradata) { hiera_file }

          it {
            is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
              %r{^.* -k #{key}$}
            )
          }
        end
      end

      context 'with privilege-related command auditing disabled' do
        let(:hieradata) { 'simp_audit_profile/disable__audit_priv_cmds' }
        [
          %r{^-a always,exit -F path=/(usr/)?bin/su -F perm=x -k privileged-priv_change$},
          %r{^-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged-priv_change$},
          %r{^-a always,exit -F path=/usr/bin/newgrp -F perm=x -k privileged-priv_change$},
          %r{^-a always,exit -F path=/usr/bin/chsh -F perm=x -k privileged-priv_change$},
          %r{^-a always,exit -F path=/(usr/)?bin/sudoedit -F perm=x -k privileged-priv_change$}
        ].each do |command_regex|
          it {
            is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').
              with_content(command_regex)
          }
        end
      end

      context 'with sudoers config auditing disabled' do
        let(:hieradata) { 'simp_audit_profile/disable__audit_cfg_sudoers' }
        [
          %r{^-w /etc/sudoers -p wa -k CFG_sys$},
          %r{^-w /etc/sudoers.d -p wa -k CFG_sys$},
        ].each do |command_regex|
          it {
            is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').
              with_content(command_regex)
          }
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
          it {
            is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').
              with_content(command_regex)
          }
        end
      end

      context 'with ptrace auditing disabled' do
        let(:hieradata) { 'simp_audit_profile/disable__audit_ptrace' }

        it {
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules'). with_content(
            %r{^-a always,exit -F arch=b\d\d -S ptrace -k paranoid$}
          )
        }
      end

      context 'with personality auditing disabled' do
        let(:hieradata) { 'simp_audit_profile/disable__audit_personality' }

        it {
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r{^-a always,exit -F arch=b\d\d -S personality -k paranoid$}
          )
        }
      end

      context 'with chmod auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_chmod' }

        it {
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r{^-a always,exit -F arch=b\d\d( -S \w*chmod\w*?)+ -k chmod$}
          )
        }
      end

      context 'with rename/remove operation auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_rename_remove' }

        it {
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F arch=b64 -S rename -S renameat -S rmdir -S unlink -S unlinkat -F perm=x -k delete)
          )
        }

        it {
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F arch=b32 -S rename -S renameat -S rmdir -S unlink -S unlinkat -F perm=x -k delete)
          )
        }
      end

      context 'with umask operations auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_umask' }

        it {
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F arch=b\d\d -S umask -k umask)
          )
        }
      end

      context 'with selinux command auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_selinux_cmds' }

        it {
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F path=/usr/bin/chcon -F perm=x -k privileged-priv_change)
          )
        }

        it {
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F path=/usr/sbin/semanage -F perm=x -k privileged-priv_change)
          )
        }

        it {
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F path=/usr/sbin/setsebool -F perm=x -k privileged-priv_change)
          )
        }

        it {
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F path=/(usr/)?sbin/setfiles -F perm=x -k privileged-priv_change)
          )
        }
      end

      context 'with yum command auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_yum_cmd' }

        it {
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-w /(usr/)?bin/yum -p x)
          )
        }
      end

      context 'with rpm command auditing enabled' do
        let(:hieradata) { 'simp_audit_profile/enable__audit_rpm_cmd' }

        it {
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-w /(usr/)?bin/rpm -p x)
          )
        }
      end


      context 'with all auditing options enabled and custom tags' do
        let(:hieradata) { 'simp_audit_profile/enable_all_custom_tags' }

        it 'uses custom tags as rule keys' do
          if os_facts[:os][:release][:major] == '6'
            expected = File.read('spec/classes/config/audit_profiles/expected/simp_el6_all_rules_custom_tags.txt')
          else
            expected = File.read('spec/classes/config/audit_profiles/expected/simp_el7_all_rules_custom_tags.txt')
          end
        end
      end

      context 'with multiple audit profiles' do
        let(:params) {{ :default_audit_profiles => ['simp', 'stig'] }}

        it {
            if os_facts[:os][:release][:major] == '6'
              expected = File.read('spec/classes/config/audit_profiles/expected/simp_el6_basic_rules.txt')
            else
              expected = File.read('spec/classes/config/audit_profiles/expected/simp_el7_basic_rules.txt')
            end
            is_expected.to contain_file('/etc/audit/rules.d/50_00_simp_base.rules').with_content(expected)
        }

        it { is_expected.to contain_file('/etc/audit/rules.d/50_01_stig_base.rules').with_content(
          /#### auditd::config::audit_profiles::stig Audit Rules ####/)
        }
      end
    end
  end
end
