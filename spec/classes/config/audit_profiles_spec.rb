require 'spec_helper'

# We have to test auditd::config::audit_profiles via auditd, because
# auditd::config::audit_profiles is private.  To take advantage of hooks
# built into puppet-rspec, the class described needs to be the class
# instantiated, i.e., auditd.
describe 'auditd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        f = Marshal.load(Marshal.dump(os_facts))
        unless f[:auditd_major_version]
          f[:auditd_major_version] = if f[:os][:release][:major].to_i < 8
                                       '2'
                                     else
                                       '3'
                                     end
        end

        f
      end

      # The audit profiles are opt-in now: auditd::config only contains
      # audit_profiles when default_audit_profiles is non-empty, and the
      # watch rules on auditd's own config are behind audit_auditd_config.
      # This file exists to test the content of that profile, so it asks for
      # it once here instead of in every context below.
      let(:base_params) do
        {
          default_audit_profiles: ['simp'],
          audit_auditd_config: true,
        }
      end

      let(:params) { base_params }

      let(:head) { '/etc/audit/rules.d/00_head.rules' }
      let(:drop) { '/etc/audit/rules.d/05_default_drop.rules' }
      let(:tail) { '/etc/audit/rules.d/99_tail.rules' }

      # The three settings files are edited in place, one file_line per
      # directive. Unset leaves a line alone (no file_line at all), false or
      # 'absent' removes it, and a value writes it.
      def written(title, line)
        contain_file_line(title).with(ensure: nil, line: line, multiple: true)
      end

      def removed(title)
        contain_file_line(title).with(ensure: 'absent', match_for_absence: true, multiple: true)
      end

      context 'with default parameters' do
        it { is_expected.to compile.with_all_deps }

        it 'seeds 00_head.rules once with -D and the packaged -b' do
          is_expected.to contain_file(head).with(
            ensure: 'file',
            replace: false,
            content: %r{^-D\n-b 8192\n\z},
          )
        end

        it 'always manages -D' do
          is_expected.to contain_file_line('00_head -D').with(path: head, line: '-D', match: '^-D\s*$')
        end

        it 'writes -c for the simp profile' do
          is_expected.to written('00_head ignore_failures', '-c')
        end

        ['ignore_errors', 'buffer_size', 'backlog_wait_time', 'failure_mode', 'rate', 'loginuid_immutable'].each do |name|
          it { is_expected.not_to contain_file_line("00_head #{name}") }
        end

        it 'declares the drop and tail files without content' do
          is_expected.to contain_file(drop).with(ensure: 'file', content: nil)
          is_expected.to contain_file(tail).with(ensure: 'file', content: nil)
        end

        it 'manages no drop rules or -e 2' do
          ['anonymous', 'system_services', 'crond', 'chrony b32', 'chrony b64', 'crypto_key_user'].each do |name|
            is_expected.not_to contain_file_line("05_default_drop #{name}")
          end
          is_expected.not_to contain_file_line('99_tail immutable')
        end

        it { is_expected.to contain_class('auditd::config::audit_profiles::simp') }
      end

      context 'with the simp:defaults preamble and drop values' do
        let(:params) do
          base_params.merge(
            buffer_size: 16_384,
            failure_mode: 1,
            rate: 0,
            loginuid_immutable: true,
            ignore_errors: true,
            ignore_failures: true,
            ignore_anonymous: true,
            ignore_system_services: true,
            ignore_crond: true,
            ignore_time_daemons: true,
            ignore_crypto_key_user: true,
            immutable: false,
          )
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_auditd__rule('audit_auditd_config').with_content(%r{-w /var/log/audit -p wa -k audit-logs}) }

        it 'writes the preamble options' do
          is_expected.to written('00_head ignore_errors', '-i')
          is_expected.to written('00_head ignore_failures', '-c')
          is_expected.to written('00_head buffer_size', '-b 16384')
          is_expected.to written('00_head failure_mode', '-f 1')
          is_expected.to written('00_head rate', '-r 0')
          is_expected.to written('00_head loginuid_immutable', '--loginuid-immutable')
        end

        it 'writes the default drop rules' do
          chrony = '-S adjtimex -F auid=-1 -F uid=chrony -F subj_type=chronyd_t'

          is_expected.to written('05_default_drop anonymous', '-a never,exit -F auid=-1')
          is_expected.to written('05_default_drop system_services', "-a never,exit -F auid!=0 -F auid<#{facts[:uid_min]}")
            .with_match('^-a never,exit -F auid!=0 -F auid<\d+$')
          is_expected.to written('05_default_drop crond', '-a never,user -F subj_type=crond_t')
          is_expected.to written('05_default_drop chrony b32', "-a never,exit -F arch=b32 #{chrony}")
          is_expected.to written('05_default_drop crypto_key_user', '-a always,exclude -F msgtype=CRYPTO_KEY_USER')

          if facts[:os][:hardware] == 'x86_64'
            is_expected.to written('05_default_drop chrony b64', "-a never,exit -F arch=b64 #{chrony}")
          else
            is_expected.not_to contain_file_line('05_default_drop chrony b64')
          end
        end

        it 'removes -e 2' do
          is_expected.to removed('99_tail immutable').with_match('^-e\s+2\s*$')
        end

        it { is_expected.to contain_class('auditd::config::audit_profiles::simp') }
      end

      # Every directive takes the same three states; unset is covered above.
      {
        'buffer_size'        => [8192, '-b 8192', 'absent'],
        'backlog_wait_time'  => [60_000, '--backlog_wait_time 60000', 'absent'],
        'failure_mode'       => [2, '-f 2', 'absent'],
        'rate'               => [100, '-r 100', 'absent'],
        'ignore_errors'      => [true, '-i', false],
        'ignore_failures'    => [true, '-c', false],
        'loginuid_immutable' => [true, '--loginuid-immutable', false],
      }.each do |name, (value, line, off)|
        context "with #{name} => #{value.inspect}" do
          let(:params) { base_params.merge(name.to_sym => value) }

          it { is_expected.to written("00_head #{name}", line).with_path(head) }
        end

        context "with #{name} => #{off.inspect}" do
          let(:params) { base_params.merge(name.to_sym => off) }

          it { is_expected.to removed("00_head #{name}").with_path(head) }
        end
      end

      {
        'ignore_anonymous'       => 'anonymous',
        'ignore_system_services' => 'system_services',
        'ignore_crond'           => 'crond',
        'ignore_time_daemons'    => 'chrony b32',
        'ignore_crypto_key_user' => 'crypto_key_user',
      }.each do |param, name|
        context "with #{param} => false" do
          let(:params) { base_params.merge(param.to_sym => false) }

          it { is_expected.to removed("05_default_drop #{name}").with_path(drop) }
        end
      end

      context 'with ignore_failures unset and only the built_in profile' do
        let(:params) { base_params.merge(default_audit_profiles: ['built_in']) }

        it { is_expected.not_to contain_file_line('00_head ignore_failures') }
      end

      context 'with only the stig profile' do
        let(:params) { base_params.merge(default_audit_profiles: ['stig']) }

        it { is_expected.to written('00_head ignore_failures', '-c') }
      end

      context 'with immutable => true' do
        let(:params) { base_params.merge(immutable: true) }

        it { is_expected.to written('99_tail immutable', '-e 2').with_path(tail) }
      end

      context 'targeting specific SELinux types' do
        context 'as an Array' do
          let(:params) { base_params.merge(target_selinux_types: ['unconfined_t', 'bob_t']) }

          it 'adds a rule to drop types not in the match list' do
            is_expected.to written('05_default_drop selinux unconfined_t', '-a never,user -F subj_type!=unconfined_t')
              .with_match('^-a never,user -F subj_type!=unconfined_t$')
            is_expected.to written('05_default_drop selinux bob_t', '-a never,user -F subj_type!=bob_t')
          end
        end

        context 'as a Hash' do
          let(:params) do
            base_params.merge(target_selinux_types: { 'unconfined_t' => {}, 'bob_t' => { 'ensure' => 'absent' } })
          end

          it 'writes present entries and removes absent ones' do
            is_expected.to written('05_default_drop selinux unconfined_t', '-a never,user -F subj_type!=unconfined_t')
            is_expected.to removed('05_default_drop selinux bob_t').with_match('^-a never,user -F subj_type!=bob_t$')
          end
        end

        context 'with a name that is not an SELinux type' do
          let(:params) { base_params.merge(target_selinux_types: ['foo.*_t']) }

          it { is_expected.not_to compile }
        end
      end

      context 'setting the root audit level to aggressive' do
        let(:params) { base_params.merge(root_audit_level: 'aggressive') }

        it { is_expected.to compile.with_all_deps }
        it 'increases the buffer size (above basic setting)' do
          is_expected.to written('00_head buffer_size', '-b 32788')
        end

        context 'with a larger buffer_size' do
          let(:params) { super().merge(buffer_size: 50_000) }

          it { is_expected.to written('00_head buffer_size', '-b 50000') }
        end

        context "with buffer_size => 'absent'" do
          let(:params) { super().merge(buffer_size: 'absent') }

          it { is_expected.to removed('00_head buffer_size') }
        end
      end

      context 'setting the root audit level to insane' do
        let(:params) { base_params.merge(root_audit_level: 'insane') }

        it { is_expected.to compile.with_all_deps }
        it 'increases the buffer size (above aggressive setting)' do
          is_expected.to written('00_head buffer_size', '-b 65576')
        end
      end

      context "setting default_audit_profiles to ['stig']" do
        let(:params) { base_params.merge(default_audit_profiles: ['stig']) }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_class('auditd::config::audit_profiles::simp') }
        it { is_expected.to contain_class('auditd::config::audit_profiles::stig') }
      end

      context "setting default_audit_profiles to ['simp', 'stig']" do
        let(:params) { base_params.merge(default_audit_profiles: ['simp', 'stig']) }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('auditd::config::audit_profiles::simp') }
        it { is_expected.to contain_class('auditd::config::audit_profiles::stig') }
      end

      context 'setting default_audit_profiles to []' do
        let(:params) { base_params.merge(default_audit_profiles: []) }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_class('auditd::config::audit_profiles::simp') }
        it { is_expected.not_to contain_class('auditd::config::audit_profiles::stig') }
      end
    end
  end
end
