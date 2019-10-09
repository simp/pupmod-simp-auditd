require 'spec_helper'

describe 'auditd::config::plugins::syslog' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:pre_condition) do
          'include "auditd"'
        end

        context 'for all versions of auditd' do
          [{ :auditd_version => "3.0", :auditd_major_version => "3"}, { :auditd_version => "2.8.4", :auditd_major_version => "2"}].each do |  more_facts |
            let(:facts) {os_facts.merge(more_facts)}
            context 'without any parameters' do
              let(:params) {{ }}
              let(:expected_content2){
<<EOM
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
              }
              let(:expected_content3){
<<EOM
# This File is managed by Puppet
#
# This file controls the configuration of the syslog plugin.
active = yes
direction = out
path = /bin/audisp-syslog
type = always
args = LOG_INFO LOG_LOCAL5
format = string
EOM
              }

              it { is_expected.to compile.with_all_deps }
              it {
                if facts['auditd_major_version'] == '3'
                  is_expected.to contain_file('/etc/audit/plugins.d/syslog.conf').with_content(expected_content3)
                  is_expected.to contain_package('audisp-syslog')
                else
                  is_expected.to contain_file('/etc/audisp/plugins.d/syslog.conf').with_content(expected_content2)
                  is_expected.to_not contain_package('audisp-syslog')
                end
              }
            end

            context 'when setting syslog priority and facility' do
              let(:params) {{
                :enable   => false,
                :facility => 'LOG_LOCAL6',
                :priority => 'LOG_NOTICE'
              }}
              let(:expected_content2) {
<<EOM
# This File is managed by Puppet
#
# This file controls the configuration of the syslog plugin.
active = no
direction = out
path = builtin_syslog
type = builtin
args = LOG_NOTICE LOG_LOCAL6
format = string
EOM
              }
              let(:expected_content3) {
<<EOM
# This File is managed by Puppet
#
# This file controls the configuration of the syslog plugin.
active = no
direction = out
path = /bin/audisp-syslog
type = always
args = LOG_NOTICE LOG_LOCAL6
format = string
EOM
              }

              it { is_expected.to compile.with_all_deps }
              it {
                if facts['auditd_major_version'] == '3'
                  is_expected.to contain_file('/etc/audit/plugins.d/syslog.conf').with_content(expected_content3)
                  is_expected.to_not contain_package('audisp-syslog')
                else
                  is_expected.to contain_file('/etc/audisp/plugins.d/syslog.conf').with_content(expected_content2)
                  is_expected.to_not contain_package('audisp-syslog')
                end
              }
            end

            context 'when syslog priority is invalid' do
            # appropriate priority for /usr/bin/logger, but not audisp
              let(:params) {{
                :priority => 'warn'
              }}
              it { is_expected.to_not compile.with_all_deps }
            end

            context 'when syslog facility is invalid' do
              # appropriate facility for /usr/bin/logger, but not audisp
              let(:params) {{
                :facility => 'local6'
              }}
              it { is_expected.to_not compile.with_all_deps }
            end
          end 
        end
      end
    end
  end
end
