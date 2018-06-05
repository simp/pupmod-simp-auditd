require 'spec_helper'

describe 'auditd::config::audit_profiles::simp' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      let(:base_audit_syscalls) do
        [
          'capset',
          'mknod',
          'pivot_root',
          'quotactl',
          'setsid',
          'settimeofday',
          'setuid',
          'swapoff',
          'swapon'
        ]
      end

      let(:aggressive_audit_syscalls) do
        base_audit_syscalls + [
          'execv',
          'rename',
          'renameat',
          'rmdir',
          'unlink',
          'unlinkat'
        ]
      end

      let(:insane_audit_syscalls) do
        base_audit_syscalls + aggressive_audit_syscalls + [
          'write',
          'chown',
          'creat',
          'fork',
          'vfork',
          'link',
          'mkdir',
          'rmdir'
        ]
      end

      it { is_expected.to compile.with_all_deps }

      context 'with default parameters' do
        it { is_expected.to contain_auditd__rule('init.d_auditd') }
        it {
          is_expected.to contain_auditd__rule('rotated_audit_logs').with_content(
            %r(-w /var/log/audit/audit.log.5 -p rwa -k audit-logs)
          )
        }

        it {
          # Ignoring Failures
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(%r(^-c$))
        }

        it {
          # Setting the Buffer Size
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
            %r(^-b\s+16384$)
          )
        }

        it {
          # Setting the failure mode
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
            %r(^-f\s+1$)
          )
        }

        it {
          # Setting the rate limiting
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
            %r(^-r\s+0$)
          )
        }

        it {
          # Dropping nonsense data
          is_expected.to contain_file('/etc/audit/rules.d/05_default_drop.rules').with_content(
            %r(^-a\s+exit,never\s+-F\s+auid=-1$)
          )
        }

        it {
          # Dropping Logs from crond
          is_expected.to contain_file('/etc/audit/rules.d/05_default_drop.rules').with_content(
            %r(^-a\s+never,user\s+-F\s+subj_type=crond_t$)
          )
        }

        it {
          # Dropping system services
          # Optimized form, drop early to reduce system load.
          is_expected.to contain_file('/etc/audit/rules.d/05_default_drop.rules').with_content(
            %r(^-a\s+exit,never\s+-F\s+auid!=0\s+-F\s+auid<#{facts[:uid_min]}$)
          )
        }

        it {
          if os_facts[:os][:release][:major] == '6'
            expected = File.read('spec/classes/config/audit_profiles/expected/basic_el6_base.rules.txt')
          else
            expected = File.read('spec/classes/config/audit_profiles/expected/basic_el7_base.rules.txt')
          end
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(expected)
        }

        it {
          # Should be well formed
          base_rules = catalogue.resource('File[/etc/audit/rules.d/50_base.rules]')[:content].split("\n")

          rules_with_tags = base_rules.select{|x| x =~ / -k / }
          rules_with_tags.delete_if{|x| x =~ / -k \S+/}

          expect(rules_with_tags).to be_empty
        }

        it {
          # Check that we have the expected audit line
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(-a always,exit -F arch=b\d\d -F auid!=0 -F uid=0 (-S .*)+ -k su-root-activity)
          )

          # Check that we're checking the appropriate syscalls
          catalogue.resource('File','/etc/audit/rules.d/50_base.rules')[:content].scan(/.*-k su-root-activity/).each do |rule_line|
            _syscalls = rule_line.scan(/-S\s.+?\s/).map{|x| x.sub(/-S\s+/,'')}.map(&:strip)

            expect(_syscalls).to_not be_empty
            expect(_syscalls - base_audit_syscalls).to be_empty
          end
        }

        # chmod is disabled by default (SIMP-2250)
        it{
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F arch=b\d\d( -S \w*chmod\w*?)+ -k chmod$)
          )
        }

        # Package command auditing is disabled by default
        it{
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-w /(usr/)?bin/rpm -p x)
          )
        }

        it{
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-w /(usr/)?bin/yum -p x)
          )
        }
      end

      context 'setting the root audit level to aggressive' do
        let(:params) {{ :root_audit_level => 'aggressive' }}

        it {
          # Setting the Buffer Size
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
            %r(^-b\s+32788$)
          )
        }

        it {
          if os_facts[:os][:release][:major] == '6'
            expected = File.read('spec/classes/config/audit_profiles/expected/aggressive_el6_base.rules.txt')
          else
            expected = File.read('spec/classes/config/audit_profiles/expected/aggressive_el7_base.rules.txt')
          end
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(expected)
        }

        it {
          # Setting what we audit for 'su' type usage
          # Check that we have the expected audit line
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(-a always,exit -F arch=b\d\d -F auid!=0 -F uid=0 (-S .*)+ -k su-root-activity)
          )

          # Check that we're checking the appropriate syscalls
          catalogue.resource('File','/etc/audit/rules.d/50_base.rules')[:content].scan(/.*-k su-root-activity/).each do |rule_line|
            _syscalls = rule_line.scan(/-S\s.+?\s/).map{|x| x.sub(/-S\s+/,'')}.map(&:strip)

            expect(_syscalls).to_not be_empty
            expect(_syscalls - aggressive_audit_syscalls).to be_empty
          end
        }
      end

      context 'setting the root audit level to insane' do
        let(:params) {{ :root_audit_level => 'insane' }}

        it {
          # Setting the Buffer Size
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
            %r(^-b\s+65576$)
          )
        }

        it {
          if os_facts[:os][:release][:major] == '6'
            expected = File.read('spec/classes/config/audit_profiles/expected/insane_el6_base.rules.txt')
          else
            expected = File.read('spec/classes/config/audit_profiles/expected/insane_el7_base.rules.txt')
          end
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(expected)
        }

        it {
          # Setting what we audit for 'su' type usage
          # Check that we have the expected audit line
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(-a always,exit -F arch=b\d\d -F auid!=0 -F uid=0 (-S .*)+ -k su-root-activity)
          )

          # Check that we're checking the appropriate syscalls
          catalogue.resource('File','/etc/audit/rules.d/50_base.rules')[:content].scan(/.*-k su-root-activity/).each do |rule_line|
            _syscalls = rule_line.scan(/-S\s.+?\s/).map{|x| x.sub(/-S\s+/,'')}.map(&:strip)

            expect(_syscalls).to_not be_empty
            expect(_syscalls - insane_audit_syscalls).to be_empty
          end
        }
      end

      context 'setting permissions auditing separated by chown, chmod, and attr' do
        let(:params) {{
          :audit_chown => false,
          :audit_chmod => true,
          :audit_attr_tag => 'fhqwhgads'
        }}

        it{
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F arch=b\d\d( -S \w*chown\w*?)+ -k chown$)
          )
        }

        it{
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F arch=b\d\d( -S \w*chmod\w*?)+ -k chmod$)
          )
        }

        it{
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-a always,exit -F arch=b\d\d( -S \w*attr\w*?)+ -k fhqwhgads$)
          )
        }
      end

      context 'auditing package installation commands' do
        let(:params) {{
          :audit_yum_cmd => true,
          :audit_rpm_cmd => true
        }}

        it{
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-w /(usr/)?bin/rpm -p x)
          )
        }

        it{
          is_expected.to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r(^-w /(usr/)?bin/yum -p x)
          )
        }
      end

      context 'disabling passwd command auditing' do
        let(:params) {{ :audit_passwd_cmds => false }}
        [
          %r{-a always,exit -F path=/usr/bin/passwd -F perm=x -k privileged-passwd},
          %r{-a always,exit -F path=/(usr/)?bin/unix_chkpwd -F perm=x -k privileged-passwd},
          %r{-a always,exit -F path=/usr/bin/gpasswd -F perm=x -k privileged-passwd},
          %r{-a always,exit -F path=/usr/bin/chage -F perm=x -k privileged-passwd},
          %r{-a always,exit -F path=/usr/sbin/userhelper -F perm=x -k privileged-passwd}
        ].each do |command_regex|
          it {
            is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').
              with_content(command_regex)
          }
        end
      end

      context 'disabling privilege-related command auditing' do
        let(:params) {{ :audit_priv_cmds => false }}
        [
          %r{-a always,exit -F path=/(usr/)?bin/su -F perm=x -k privileged-priv_change},
          %r{-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged-priv_change},
          %r{-a always,exit -F path=/usr/bin/newgrp -F perm=x -k privileged-priv_change},
          %r{-a always,exit -F path=/usr/bin/chsh -F perm=x -k privileged-priv_change},
          %r{-a always,exit -F path=/(usr/)?bin/sudoedit -F perm=x -k privileged-priv_change}
        ].each do |command_regex|
          it {
            is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').
              with_content(command_regex)
          }
        end
      end

      context 'disabling postfix-related command auditing' do
        let(:params) {{ :audit_postfix_cmds => false }}
        [
          %r{-a always,exit -F path=/usr/sbin/postdrop -F perm=x -k privileged-postfix},
          %r{-a always,exit -F path=/usr/sbin/postqueue -F perm=x -k privileged-postfix}
        ].each do |command_regex|
          it {
            is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').
              with_content(command_regex)
          }
        end
      end

      context 'disabling ssh-keysign command auditing' do
        let(:params) {{ :audit_ssh_keysign_cmd => false }}
        it {
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r{-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -k privileged-ssh}
          )
        }

      end

      context 'disabling crontab command auditing' do
        let(:params) {{ :audit_crontab_cmd => false }}
        it {
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r{-a always,exit -F path=/usr/bin/crontab -F perm=x -k privileged-cron}
          )
        }
      end

      context 'disabling pam-timestamp-check command auditing' do
        let(:params) {{ :audit_pam_timestamp_check_cmd => false }}
        it {
          is_expected.not_to contain_file('/etc/audit/rules.d/50_base.rules').with_content(
            %r{-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -k privileged-pam}
          )
        }
      end
    end
  end
end
