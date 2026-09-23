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

      # The preamble options and default drop rules are opt-in: unset, none of
      # them are written. simp:defaults sets the values asserted further down.
      context 'with default parameters' do
        it { is_expected.to compile.with_all_deps }

        it 'writes no preamble options' do
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules')
            .without_content(%r{^-[icbfr](\s|$)})
            .without_content(%r{^--loginuid-immutable$})
        end

        it 'writes no default drop rules' do
          is_expected.to contain_file('/etc/audit/rules.d/05_default_drop.rules')
            .without_content(%r{^-a\s+never,exit\s+-F\s+auid=-1$})
            .without_content(%r{^-a\s+never,user\s+-F\s+subj_type=crond_t$})
            .without_content(%r{^-a\s+never,exit\s+-F\s+auid!=0\s+-F\s+auid<})
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
          )
        end

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
      end

      context 'targeting specific SELinux types' do
        let(:params) do
          base_params.merge(target_selinux_types: ['unconfined_t', 'bob_t'])
        end

        it 'adds a rule to drop types not in the match list' do
          is_expected.to contain_file('/etc/audit/rules.d/05_default_drop.rules').with_content(
            %r{^-a\s+never,user\s+-F\s+subj_type!=unconfined_t$},
          )

          is_expected.to contain_file('/etc/audit/rules.d/05_default_drop.rules').with_content(
            %r{^-a\s+never,user\s+-F\s+subj_type!=bob_t$},
          )
        end
      end

      context 'setting the root audit level to aggressive' do
        let(:params) { base_params.merge(root_audit_level: 'aggressive') }

        it { is_expected.to compile.with_all_deps }
        it 'increases the buffer size (above basic setting)' do
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
            %r{^-b\s+32788$},
          )
        end
      end

      context 'setting the root audit level to insane' do
        let(:params) { base_params.merge(root_audit_level: 'insane') }

        it { is_expected.to compile.with_all_deps }
        it 'increases the buffer size (above aggressive setting)' do
          is_expected.to contain_file('/etc/audit/rules.d/00_head.rules').with_content(
            %r{^-b\s+65576$},
          )
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
