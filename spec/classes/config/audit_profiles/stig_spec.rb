require 'spec_helper'
require_relative '../../../support/file_lines'

# We have to test auditd::config::audit_profiles::stig via auditd,
# because auditd::config::audit_profiles::stig is private.  To take
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

  let(:path) { '/etc/audit/rules.d/50_00_stig_base.rules' }
  let(:base_10x) { File.read('spec/classes/config/audit_profiles/expected/stig_base_rules.txt') }
  let(:rules) { apply_file_lines(catalogue, path) }
  let(:upgraded) { apply_file_lines(catalogue, path, base_10x) }

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile.with_all_deps }

      context 'with no toggle set' do
        let(:hiera_config) { File.expand_path('../../../fixtures/hieradata/hiera.yaml', __dir__) }
        let(:params) { { default_audit_profiles: ['stig'] } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_file(path) }

        # Undeclared, the purge would delete the file.
        context 'with the purge on' do
          let(:params) { { default_audit_profiles: ['stig'], purge_auditd_rules: true } }

          it { is_expected.to contain_file(path).with(ensure: 'file', content: nil) }

          it 'edits no rule' do
            expect(catalogue.resources.select { |r| r.type == 'File_line' && r[:path] == path }).to be_empty
          end
        end
      end

      context 'with the simp:defaults toggles' do
        let(:params) { { default_audit_profiles: ['stig'] } }

        it 'writes the rules 10.x wrote, in the same order' do
          expect(rules).to eq(rules_in(base_10x))
        end

        it 'leaves the file 10.x wrote unchanged' do
          expect(upgraded).to eq(base_10x)
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
      end

      # auid>=N is matched as any number, so a changed uid_min replaces each
      # rule in place.
      context 'with a changed uid_min' do
        let(:params) { { default_audit_profiles: ['stig'], uid_min: 500 } }

        it 'replaces the rules in place' do
          expect(upgraded).to eq(base_10x.gsub('auid>=1000', 'auid>=500'))
        end
      end

      # check disabling of parameters for which the key is unique
      { 'access'                      => 'stig_audit_profile/disable__audit_unsuccessful_file_operations',
        'delete'                      => 'stig_audit_profile/disable__audit_rename_remove',
        'setuid/setgid'               => 'stig_audit_profile/disable__audit_suid_sgid',
        'module-change'               => 'stig_audit_profile/disable__audit_kernel_modules',
        'privileged-mount'            => 'stig_audit_profile/disable__audit_mount',
        'identity'                    => 'stig_audit_profile/disable__audit_local_account',
        'logins'                      => 'stig_audit_profile/disable__audit_login_files',
        'privileged-actions'          => 'stig_audit_profile/disable__audit_cfg_sudoers',
        'privileged-passwd'           => 'stig_audit_profile/disable__audit_passwd_cmds',
        'privileged-postfix'          => 'stig_audit_profile/disable__audit_postfix_cmds',
        'privileged-ssh'              => 'stig_audit_profile/disable__audit_ssh_keysign_cmd',
        'privileged-cron'             => 'stig_audit_profile/disable__audit_crontab_cmd',
        'privileged-pam'              => 'stig_audit_profile/disable__audit_pam_timestamp_check_cmd', }.each do |key, hiera_file|
        context "with #{key} auditing disabled" do
          let(:params) { { default_audit_profiles: ['stig'] } }
          let(:hieradata) { hiera_file }

          it { expect(rules).not_to match(%r{^.* -F key=#{key}$}) }

          it 'removes the rules from an existing file' do
            expect(base_10x).to match(%r{^.* -F key=#{key}$})
            expect(upgraded).not_to match(%r{^.* -F key=#{key}$})
          end
        end
      end

      context 'with suid_sgid_cmds entries set to absent' do
        let(:params) { { default_audit_profiles: ['stig'] } }
        let(:hieradata) { 'stig_audit_profile/absent__suid_sgid_cmds_entries' }

        it { expect(rules).not_to include('-F path=/usr/bin/at -F perm=x') }

        # /usr/bin/passwd is also an audit_passwd_cmds rule, matched by key.
        it 'removes only those setuid/setgid rules from an existing file' do
          expect(upgraded).to eq(
            base_10x.sub("-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=unset -F key=setuid/setgid\n", '')
                    .sub("-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -F key=setuid/setgid\n", ''),
          )
          expect(upgraded).to include('-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged-passwd')
        end
      end

      context 'with chown auditing disabled' do
        let(:params) { { default_audit_profiles: ['stig'] } }
        let(:hieradata) { 'stig_audit_profile/disable__audit_chown' }

        it { expect(rules).not_to match(%r{^-a always,exit -F arch=b\d\d -S \w*chown\w* -F auid>=\d+ -F auid!=unset -F key=perm_mod$}) }
        it { expect(upgraded).not_to match(%r{^-a always,exit -F arch=b\d\d -S \w*chown\w* -F auid>=\d+ -F auid!=unset -F key=perm_mod$}) }
      end

      context 'with chmod auditing disabled' do
        let(:params) { { default_audit_profiles: ['stig'] } }
        let(:hieradata) { 'stig_audit_profile/disable__audit_chmod' }

        it { expect(rules).not_to match(%r{^-a always,exit -F arch=b\d\d -S \w*chmod\w* -F auid>=\d+ -F auid!=unset -F key=perm_mod$}) }
        it { expect(upgraded).not_to match(%r{^-a always,exit -F arch=b\d\d -S \w*chmod\w* -F auid>=\d+ -F auid!=unset -F key=perm_mod$}) }
      end

      context 'with attr auditing disabled' do
        let(:params) { { default_audit_profiles: ['stig'] } }
        let(:hieradata) { 'stig_audit_profile/disable__audit_attr' }

        it { expect(rules).not_to match(%r{^-a always,exit -F arch=b\d\d -S \w*attr -F auid>=\d+ -F auid!=unset -F key=perm_mod$}) }
        it { expect(upgraded).not_to match(%r{^-a always,exit -F arch=b\d\d -S \w*attr -F auid>=\d+ -F auid!=unset -F key=perm_mod$}) }
      end

      context 'with selinux command auditing disabled' do
        let(:params) { { default_audit_profiles: ['stig'] } }
        let(:hieradata) { 'stig_audit_profile/disable__audit_selinux_cmds' }

        [
          %r{^-a always,exit -F path=/usr/bin/(chcon|semanage|setsebool) -F perm=x -F auid>=\d+ -F auid!=unset -F key=privileged-priv_change},
          %r{^-a always,exit -F path=/(usr/)?sbin/setfiles -F perm=x -F auid>=\d+ -F auid!=unset -F key=privileged-priv_change},
        ].each do |command_regex|
          it { expect(rules).not_to match(command_regex) }
          it { expect(upgraded).not_to match(command_regex) }
        end
      end

      context 'with privilege-related command auditing disabled' do
        let(:params) { { default_audit_profiles: ['stig'] } }
        let(:hieradata) { 'stig_audit_profile/disable__audit_priv_cmds' }

        [
          %r{^-a always,exit -F path=/(usr/)?bin/su -F perm=x -F auid>=\d+ -F auid!=unset -F key=privileged-priv_change$},
          %r{^-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=\d+ -F auid!=unset -F key=privileged-priv_change$},
          %r{^-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=\d+ -F auid!=unset -F key=privileged-priv_change$},
          %r{^-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=\d+ -F auid!=unset -F key=privileged-priv_change$},
          %r{^-a always,exit -F path=/(usr/)?bin/sudoedit -F perm=x -F auid>=\d+ -F auid!=unset -F key=privileged-priv_change$},
        ].each do |command_regex|
          it { expect(rules).not_to match(command_regex) }
          it { expect(upgraded).not_to match(command_regex) }
        end
      end

      context 'with all custom tags' do
        let(:params) { { default_audit_profiles: ['stig'] } }
        let(:hieradata) { 'stig_audit_profile/all_custom_tags' }

        let(:custom_10x) { File.read('spec/classes/config/audit_profiles/expected/stig_all_custom_tags.txt') }

        it 'converges in one run' do
          expect(file_line_changes(catalogue, path, rules)).to eq([])
          expect(file_line_changes(catalogue, path, upgraded)).to eq([])
        end

        it 'uses custom tags as rule keys' do
          expect(rules).to eq(rules_in(custom_10x))
        end

        # A rule that two toggles write, each with its own key, is matched
        # with its key too, so a changed tag adds a line for it and leaves the
        # old one. Every other rule is replaced in place.
        it 'replaces the tags in an existing file in place, except on shared rules' do
          body = ->(l) { l.sub(%r{ (-k |-F key=)\S+$}, '') }
          shared = rules_in(base_10x).lines.map(&body).tally.select { |_, n| n > 1 }.keys
          left_behind = rules_in(upgraded).lines - rules_in(custom_10x).lines

          expect(shared).not_to be_empty
          expect(rules_in(custom_10x).lines - rules_in(upgraded).lines).to eq([])
          expect(left_behind).not_to be_empty
          expect(left_behind - rules_in(base_10x).lines).to eq([])
          expect(left_behind.map(&body) - shared).to eq([])
        end
      end

      context 'with multiple audit profiles' do
        let(:params) { { default_audit_profiles: ['stig', 'simp'] } }

        it { expect(rules).to eq(rules_in(base_10x)) }
        it { is_expected.to contain_file('/etc/audit/rules.d/50_01_simp_base.rules') }
      end
    end
  end
end
