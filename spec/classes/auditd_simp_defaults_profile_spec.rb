# frozen_string_literal: true

require 'spec_helper'
require 'yaml'

# Tests the `simp:defaults` Sicura Compliance Engine profile end to end: with
# `compliance_engine::enforcement: [simp:defaults]` in Hiera, the otherwise
# no-op `include auditd` must reproduce the configuration the module managed by
# default before 11.0.0.
#
# The "bare include is a no-op" regression specs live in init_spec.rb and
# config_spec.rb and are intentionally left alone -- they guard the safe default
# when the profile is NOT enforced.
describe 'auditd' do
  def self.profile_dir
    File.expand_path('../../SIMP/compliance_profiles', __dir__)
  end

  # The auditd.conf keys the profile is expected to write, and their values.
  # Note the keys are not all named after the parameter that supplies them:
  # write_logs is rendered as yes/no, and name_format drags `name` in with it.
  PROFILE_INI_SETTINGS = {
    'log_file' => '/var/log/audit/audit.log',
    'log_format' => 'raw',
    'log_group' => 'root',
    'priority_boost' => 4,
    'flush' => 'incremental',
    'freq' => 20,
    'num_logs' => 5,
    'max_log_file' => 24,
    'max_log_file_action' => 'rotate',
    'space_left' => 80,
    'space_left_action' => 'syslog',
    'admin_space_left' => 50,
    'admin_space_left_action' => 'rotate',
    'disk_full_action' => 'rotate',
    'disk_error_action' => 'syslog',
    'action_mail_acct' => 'root',
    'name_format' => 'USER',
    'write_logs' => 'yes',
    'overflow_action' => 'SYSLOG',
    'q_depth' => 160,
    'max_restarts' => 10,
  }.freeze

  # Keys the profile deliberately leaves alone, so whatever the package shipped
  # survives.
  UNMANAGED_INI_SETTINGS = ['local_events', 'verify_email', 'plugin_dir'].freeze

  let(:hiera_config) do
    File.expand_path('../fixtures/hieradata/hiera_compliance_engine.yaml', __dir__)
  end

  # ---------------------------------------------------------------------------
  # Profile/check data integrity. No catalogue compilation.
  # ---------------------------------------------------------------------------
  context 'profile data' do
    let(:checks) { YAML.safe_load_file(File.join(self.class.profile_dir, 'checks.yaml'))['checks'] }
    let(:profile) { YAML.safe_load_file(File.join(self.class.profile_dir, 'profile-simp_defaults.yaml'))['profiles']['simp:defaults'] }

    it 'lists exactly the defined checks (no orphans, none missing)' do
      expect(profile['checks'].keys.sort).to eq(checks.keys.sort)
    end

    it 'only manages auditd:: parameters' do
      params = checks.values.map { |c| c['settings']['parameter'] }
      expect(params).to all(start_with('auditd::'))
    end

    # A check naming a parameter that does not exist binds nothing and fails
    # silently, which is the failure mode this file exists to prevent.
    it 'names only parameters the auditd classes actually declare' do
      missing = checks.values.map { |c| c['settings']['parameter'] }.reject do |param|
        klass, _, name = param.rpartition('::')
        manifest = (klass == 'auditd') ? 'init' : klass.delete_prefix('auditd::').tr(':', '/').squeeze('/')
        src = File.read(File.expand_path("../../manifests/#{manifest}.pp", __dir__))
        src.match?(%r{^\s+\S.*\$#{Regexp.escape(name)}\s+=})
      end
      expect(missing).to be_empty
    end

    # The rule profile toggles are parameters of private classes. Anything
    # else under auditd::config is a mistake.
    it 'reaches into no private class but the rule profiles' do
      params = checks.values.map { |c| c['settings']['parameter'] }
      expect(params.grep(%r{\Aauditd::.+::}).grep_v(%r{\Aauditd::config::audit_profiles::(simp|stig)::\w+\z})).to eq([])
    end
  end

  # ---------------------------------------------------------------------------
  # Enforced, no overrides: reproduces the pre-11.0.0 catalogue.
  #
  # auditd_version is pinned rather than swept. The version-derived keys
  # (log_format, write_logs) are already covered across three versions in
  # config_spec.rb; what is under test here is the profile, not the derivation.
  # ---------------------------------------------------------------------------
  context 'when enforcing simp:defaults' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        # $auditd::lname defaults to the FQDN, which Puppet resolves from the
        # node rather than from os_facts. Naming the node makes the `name` key
        # below assert a value we chose.
        let(:node) { 'audit.example.test' }

        let(:facts) do
          os_facts.merge(
            custom_hiera: 'simp_defaults_enforced',
            auditd_version: '3.0',
            auditd_major_version: '3',
          )
        end

        it { is_expected.to compile.with_all_deps }

        it 'installs the package' do
          is_expected.to contain_package('audit')
        end

        it 'runs and enables the service' do
          is_expected.to contain_service('auditd').with(ensure: 'running', enable: true)
        end

        it 'puts audit=1 on the kernel command line' do
          is_expected.to contain_class('auditd::config::grub').with_enable(true)
        end

        it 'writes the simp rule profile and purges rules.d' do
          is_expected.to contain_class('auditd::config::audit_profiles::simp')
          is_expected.to contain_file('/etc/audit/rules.d').with(ensure: 'directory', purge: true, recurse: true)
          is_expected.to contain_file('/etc/audit/rules.d/50_00_simp_base.rules')
          is_expected.to contain_file('/etc/audit/rules.d/75.audit_auditd_config.rules')
        end

        # Opt-in since 11.0.0; the profile restores the old preamble options.
        it 'writes the preamble options' do
          {
            'ignore_errors'   => '-i',
            'ignore_failures' => '-c',
          }.each do |name, line|
            is_expected.to contain_file_line("00_head #{name}").with(path: '/etc/audit/rules.d/00_head.rules', line: line)
          end
          {
            'buffer_size'        => '-b 16384',
            'failure_mode'       => '-f 1',
            'rate'               => '-r 0',
            'loginuid_immutable' => '--loginuid-immutable',
          }.each do |name, line|
            is_expected.to contain_file_line("rule settings #{name}").with(path: '/etc/audit/rules.d/puppet_auditd.rules', line: line)
          end
        end

        it 'writes the default drop rules' do
          is_expected.to contain_file_line('05_default_drop anonymous').with_line('-a never,exit -F auid=-1')
          is_expected.to contain_file_line('05_default_drop system_services').with_line(%r{^-a never,exit -F auid!=0 -F auid<\d+$})
          is_expected.to contain_file_line('05_default_drop crond').with_line('-a never,user -F subj_type=crond_t')
          is_expected.to contain_file_line('05_default_drop chrony b32').with_line(%r{subj_type=chronyd_t$})
          is_expected.to contain_file_line('05_default_drop crypto_key_user').with_line('-a always,exclude -F msgtype=CRYPTO_KEY_USER')
        end

        # 10.x wrote a tail without -e 2; simp:defaults reproduces that.
        it 'removes -e 2' do
          is_expected.to contain_file_line('99_tail immutable').with(ensure: 'absent', path: '/etc/audit/rules.d/99_tail.rules')
        end

        it 'takes ownership of the log directory and the config file' do
          is_expected.to contain_file('/var/log/audit').with(ensure: 'directory', owner: 'root', group: 'root')
          is_expected.to contain_file('/etc/audit/auditd.conf').with(owner: 'root', group: 'root')
        end

        PROFILE_INI_SETTINGS.each do |setting, value|
          it "sets #{setting} to #{value}" do
            is_expected.to contain_ini_setting("auditd.conf #{setting}").with_value(value)
          end
        end

        # name has no parameter of its own; name_format pulls it in.
        it 'writes the node name alongside name_format' do
          is_expected.to contain_ini_setting('auditd.conf name').with_value('audit.example.test')
        end

        UNMANAGED_INI_SETTINGS.each do |setting|
          it "leaves #{setting} to the package" do
            is_expected.not_to contain_ini_setting("auditd.conf #{setting}")
          end
        end

        # syslog still follows simp_options::syslog, which is unset here.
        it 'leaves syslog forwarding to simp_options' do
          is_expected.to contain_class('auditd').with_syslog(false)
          is_expected.not_to contain_class('rsyslog')
        end

        # Removed in 11.0.0 and not restored by the profile (see checks.yaml).
        it 'does not bring back the /etc/audit purge' do
          is_expected.not_to contain_file('/etc/audit')
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Backend wired up but enforcing nothing. Distinct from the init_spec no-op
  # tests: those never load the compliance engine at all, so only this one can
  # catch profile data being applied merely because it was found.
  # ---------------------------------------------------------------------------
  context 'without enforcement' do
    let(:facts) do
      on_supported_os.first[1].merge(
        custom_hiera: 'simp_defaults_disabled',
        auditd_version: '3.0',
        auditd_major_version: '3',
      )
    end

    it { is_expected.to compile.with_all_deps }

    it 'still manages only the package' do
      is_expected.to contain_package('audit')
      is_expected.not_to contain_service('auditd')
      is_expected.not_to contain_class('auditd::config::grub')
      is_expected.not_to contain_file('/var/log/audit')
      is_expected.not_to contain_file('/etc/audit/auditd.conf')
      is_expected.not_to contain_file('/etc/audit/rules.d')
    end

    it 'writes no auditd.conf keys' do
      expect(catalogue.resources.select { |r| r.type == 'Ini_setting' }).to be_empty
    end
  end

  # ---------------------------------------------------------------------------
  # Enforced + explicit site value. The site sits above the compliance engine
  # in the hierarchy, so it must win.
  # ---------------------------------------------------------------------------
  context 'when an explicit Hiera value overrides the profile' do
    let(:facts) do
      on_supported_os.first[1].merge(
        custom_hiera: 'simp_defaults_with_override',
        auditd_version: '3.0',
        auditd_major_version: '3',
      )
    end

    it { is_expected.to compile.with_all_deps }

    it 'uses the site max_log_file instead of the profile default' do
      is_expected.to contain_ini_setting('auditd.conf max_log_file').with_value(8)
    end

    it 'leaves the rest of the profile in force' do
      is_expected.to contain_ini_setting('auditd.conf num_logs').with_value(5)
      is_expected.to contain_service('auditd').with(ensure: 'running', enable: true)
    end
  end
end
