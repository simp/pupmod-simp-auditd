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
              auditd2 = more_facts[:auditd_major_version] == '2'
              plugin_conf = auditd2 ? '/etc/audisp/plugins.d/syslog.conf' : '/etc/audit/plugins.d/syslog.conf'
              plugin_path = auditd2 ? 'builtin_syslog' : '/sbin/audisp-syslog'
              plugin_type = auditd2 ? 'builtin' : 'always'

              context 'without any parameters' do
                let(:params) { {} }

                let(:expected_content) do
                  <<~EOM
                  # This File is managed by Puppet
                  #
                  # This file controls the configuration of the syslog plugin.
                  active = yes
                  direction = out
                  path = #{plugin_path}
                  type = #{plugin_type}
                  args = LOG_INFO LOG_LOCAL5
                  format = string
                EOM
                end

                it { is_expected.to compile.with_all_deps }
                it { is_expected.to contain_file(plugin_conf).with_content(expected_content) }

                # audispd-plugins is still version-gated: the plugin only became
                # a separate package at auditd 3.0.
                it {
                  if facts[:auditd_major_version] == '2'
                    is_expected.not_to contain_package('audispd-plugins')
                  else
                    is_expected.to contain_package('audispd-plugins')
                  end
                }
                it { is_expected.not_to contain_rsyslog__rule__drop('audispd') }
              end

              # Explicit parameters override the version-detected defaults on
              # every version.
              context 'with the auditd 2 plugin layout set explicitly' do
                let(:pre_condition) do
                  <<~PC
                    class { 'auditd': plugin_dir => '/etc/audisp/plugins.d' }
                  PC
                end
                let(:params) do
                  {
                    syslog_path: 'builtin_syslog',
                    type: 'builtin',
                  }
                end
                let(:expected_content) do
                  <<~EOM
                  # This File is managed by Puppet
                  #
                  # This file controls the configuration of the syslog plugin.
                  active = yes
                  direction = out
                  path = builtin_syslog
                  type = builtin
                  args = LOG_INFO LOG_LOCAL5
                  format = string
                EOM
                end

                it { is_expected.to compile.with_all_deps }
                it { is_expected.to contain_file('/etc/audisp/plugins.d/syslog.conf').with_content(expected_content) }
              end

              context 'when setting rsyslog, syslog priority and facility' do
                let(:params) do
                  {
                    enable: false,
                    rsyslog: true,
                    facility: 'LOG_LOCAL6',
                    priority: 'LOG_NOTICE',
                  }
                end
                let(:expected_content) do
                  <<~EOM
                  # This File is managed by Puppet
                  #
                  # This file controls the configuration of the syslog plugin.
                  active = no
                  direction = out
                  path = #{plugin_path}
                  type = #{plugin_type}
                  args = LOG_NOTICE LOG_LOCAL6
                  format = string
                EOM
                end

                it { is_expected.to compile.with_all_deps }
                it { is_expected.to contain_file(plugin_conf).with_content(expected_content) }
                it { is_expected.not_to contain_package('audisp-syslog') }
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

              # An undef argument or a Hiera ~ falls through to the code
              # default, so the default has to be undef and the value has to
              # come from module data for the opt-out to work.
              context 'with pkg_name set to ~ in hiera' do
                let(:hieradata) { 'syslog_pkg_unmanaged' }

                it { is_expected.to compile.with_all_deps }
                it { is_expected.not_to contain_package('audispd-plugins') }
                it { is_expected.to contain_file(plugin_conf) }
              end
            end
          end
        end
      end
    end
  end
end
