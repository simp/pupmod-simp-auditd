require 'spec_helper'

describe 'auditd::config::audit_profiles::simp' do
  context 'supported operating systems' do

    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          if ['RedHat','CentOS'].include?(facts[:operatingsystem]) &&
             (facts[:operatingsystemmajrelease].to_s < '7')

            facts[:apache_version] = '2.2'
            facts[:grub_version] = '0.9'
            facts[:uid_min] = '500'
          else
            facts[:apache_version] = '2.4'
            facts[:grub_version] = '2.0~beta'
            facts[:uid_min] = '1000'
          end

          facts
        end

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

        it { is_expected.to compile.with_all_deps }

        context "without any parameters" do
          let(:params) {{ }}
          it { is_expected.to contain_auditd__add_rules('init.d_auditd') }
          it {
            is_expected.to contain_auditd__add_rules('rotated_audit_logs').with_content(
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
              %r(^-f\s+2$)
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

          if ['RedHat','CentOS'].include?(facts[:operatingsystem]) &&
             (facts[:operatingsystemmajrelease].to_s < '7')

            _uid = '500'
          else
            _uid = '1000'
          end

          it {
            # Dropping system services
            # Optimized form, drop early to reduce system load.
            is_expected.to contain_file('/etc/audit/rules.d/05_default_drop.rules').with_content(
              %r(^-a\s+exit,never\s+-F\s+auid!=0\s+-F\s+auid<#{_uid}$)
            )
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
        end

        context "setting the root audit level to aggressive" do

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
              'swapon',
              'execve'
            ]
          end

          let(:params) {{
            :root_audit_level => 'aggressive'
          }}

          it {
            # Setting the Buffer Size
            is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
              %r(^-b\s+32788$)
            )
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
              expect(_syscalls - base_audit_syscalls).to be_empty
            end
          }
        end

        context "setting the root audit level to insane" do

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
              'swapon',
              'execve',
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

          let(:params) {{
            :root_audit_level => 'insane'
          }}

          it {
            # Setting the Buffer Size
            is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
              %r(^-b\s+65576$)
            )
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
              expect(_syscalls - base_audit_syscalls).to be_empty
            end
          }
        end
      end
    end
  end
end
