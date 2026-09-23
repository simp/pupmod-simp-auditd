require 'spec_helper'

describe 'auditd::config::audisp::syslog' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:pre_condition) do
          'include "auditd"'
        end

        # Test if auditd version is not defined that it finds defaults.
        # This will be the case first time it is run if auditd is not installed
        # already.
        context 'if auditd version is unknown' do
          let(:facts) { os_facts.reject { |k, _v| k == :auditd_major_version } }

          it { is_expected.to compile.with_all_deps }
        end

        # On a first run, auditd_version is missing until auditctl exists. On
        # EL10 that's the audit-rules package the module installs in the same
        # run, so the plugin must not wait for the fact.
        context 'if auditd_version is missing too' do
          let(:facts) { os_facts.reject { |k, _v| [:auditd_version, :auditd_major_version, :simplib__auditd].include?(k) } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_package('audispd-plugins') }
        end

        context 'for all versions of auditd' do
          [{ auditd_version: '4.0', auditd_major_version: '4' }, { auditd_version: '3.0', auditd_major_version: '3' }, { auditd_version: '2.8.4', auditd_major_version: '2' }].each do |more_facts|
            context "with auditd version #{more_facts[:auditd_major_version]}" do
              let(:facts) { os_facts.merge(more_facts) }

              # auditd 2 ran the syslog plugin inside audispd, configured from
              # /etc/audisp; the defaults follow the detected version. That path
              # is deprecated and goes away in 12.0.0.
              let(:auditd2) { more_facts[:auditd_major_version] == '2' }
              let(:plugin_conf) { auditd2 ? '/etc/audisp/plugins.d/syslog.conf' : '/etc/audit/plugins.d/syslog.conf' }
              let(:plugin_path) { auditd2 ? 'builtin_syslog' : '/sbin/audisp-syslog' }
              let(:plugin_type) { auditd2 ? 'builtin' : 'always' }

              # Checks the ini_setting edits to syslog.conf: `settings` must be
              # exactly the keys written, and every other key is left to the package.
              def expect_syslog_conf(path, settings)
                settings.each do |key, value|
                  is_expected.to contain_ini_setting("syslog.conf #{key}").with(
                    path: path,
                    section: '',
                    key_val_separator: ' = ',
                    setting: key,
                    value: value,
                  )
                end
                (['active', 'direction', 'path', 'type', 'args', 'format'] - settings.keys).each do |key|
                  is_expected.not_to contain_ini_setting("syslog.conf #{key}")
                end
              end

              context 'without any parameters' do
                let(:params) { {} }

                it { is_expected.to compile.with_all_deps }

                # The package's own syslog.conf is edited in place, never
                # replaced: the File carries attributes only.
                it {
                  is_expected.to contain_file(plugin_conf).with(owner: 'root', content: nil, source: nil, ensure: nil)
                }

                # On auditd 3+ the packaged file already has direction, path,
                # type and format; auditd 2 needs the builtin plugin written.
                it {
                  if auditd2
                    expect_syslog_conf(plugin_conf, 'active' => 'yes', 'direction' => 'out', 'path' => plugin_path,
                                                    'type' => plugin_type, 'args' => 'LOG_INFO LOG_LOCAL5', 'format' => 'string')
                  else
                    expect_syslog_conf(plugin_conf, 'active' => 'yes', 'args' => 'LOG_INFO LOG_LOCAL5')
                  end
                }

                # audispd-plugins is still version-gated: the plugin only became
                # a separate package at auditd 3.0. Where it is managed, the edits
                # wait for it, or the package's copy would land as .rpmnew.
                it {
                  if auditd2
                    is_expected.not_to contain_package('audispd-plugins')
                  else
                    is_expected.to contain_package('audispd-plugins')
                    is_expected.to contain_file(plugin_conf).that_requires('Package[audispd-plugins]')
                  end
                }
                it { is_expected.to contain_ini_setting('syslog.conf active').that_requires("File[#{plugin_conf}]") }
                it { is_expected.not_to contain_rsyslog__rule__drop('audispd') }
              end

              # Explicit parameters override the version-detected defaults on
              # every version, and are written because a site asked for them.
              context 'with syslog_path and type set explicitly' do
                let(:params) do
                  {
                    syslog_path: '/usr/local/sbin/audisp-syslog',
                    type: 'builtin',
                  }
                end

                it { is_expected.to compile.with_all_deps }
                it { is_expected.to contain_ini_setting('syslog.conf path').with_value('/usr/local/sbin/audisp-syslog') }
                it { is_expected.to contain_ini_setting('syslog.conf type').with_value('builtin') }
              end

              # A relocated plugin_dir has no packaged syslog.conf in it, so
              # every key is written.
              context 'with plugin_dir relocated' do
                let(:pre_condition) do
                  <<~PC
                    class { 'auditd': plugin_dir => '/opt/audit/plugins.d' }
                  PC
                end

                it { is_expected.to compile.with_all_deps }
                it {
                  expect_syslog_conf('/opt/audit/plugins.d/syslog.conf', 'active' => 'yes', 'direction' => 'out', 'path' => plugin_path,
                                                                        'type' => plugin_type, 'args' => 'LOG_INFO LOG_LOCAL5', 'format' => 'string')
                }
              end

              context 'with custom syslog priority and facility' do
                let(:params) do
                  {
                    facility: 'LOG_LOCAL6',
                    priority: 'LOG_NOTICE',
                  }
                end

                it { is_expected.to compile.with_all_deps }
                it { is_expected.to contain_ini_setting('syslog.conf args').with_value('LOG_NOTICE LOG_LOCAL6') }
              end

              # Disabled, the plugin is switched off and nothing else is
              # written, so a file is never filled in for a plugin nothing starts.
              context 'when setting rsyslog with the plugin disabled' do
                let(:params) do
                  {
                    enable: false,
                    rsyslog: true,
                    facility: 'LOG_LOCAL6',
                    priority: 'LOG_NOTICE',
                  }
                end

                it { is_expected.to compile.with_all_deps }
                it { expect_syslog_conf(plugin_conf, 'active' => 'no') }
                it { is_expected.not_to contain_package('audispd-plugins') }
                it { is_expected.to contain_class('rsyslog') }
                it { is_expected.to contain_rsyslog__rule__drop('audispd') }
              end

              context 'when syslog priority is invalid' do
                # appropriate priority for /usr/bin/logger, but not audisp
                let(:params) do
                  {
                    priority: 'warn',
                  }
                end

                it { is_expected.not_to compile.with_all_deps }
              end

              context 'when syslog facility is invalid' do
                # appropriate facility for /usr/bin/logger, but not audisp
                let(:params) do
                  {
                    facility: 'local6',
                  }
                end

                it { is_expected.not_to compile.with_all_deps }
              end

              # 10.x let a site set this to ~ to skip the package. The value
              # comes from module data and the parameter is a required
              # String[1], so ~ now fails at the parameter, by name.
              context 'with pkg_name set to ~ in hiera' do
                let(:hieradata) { 'syslog_pkg_unmanaged' }

                it { is_expected.to compile.and_raise_error(%r{'pkg_name' expects a String value, got Undef}) }
              end
            end
          end
        end
      end
    end
  end
end
