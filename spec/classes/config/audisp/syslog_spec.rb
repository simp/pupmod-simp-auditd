require 'spec_helper'

describe 'auditd::config::audisp::syslog' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:pre_condition) do
          'include "auditd"'
        end

        let(:facts){ facts }

        context "without any parameters" do
          let(:params) {{ }}
          let(:expected_content) {
<<EOM
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_INFO LOG_LOCAL5
format = string
EOM
          }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/etc/audisp/plugins.d/syslog.conf').with_content(expected_content)
          }
          it {
            is_expected.to contain_rsyslog__rule__drop('audispd').with_rule(%r(\$programname == 'audispd'))
          }
        end

        context "when setting syslog priority and facility" do
          let(:params) {{
            :facility => 'LOG_LOCAL6',
            :priority => 'LOG_NOTICE'
          }}
          let(:expected_content) {
<<EOM
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_NOTICE LOG_LOCAL6
format = string
EOM
          }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/etc/audisp/plugins.d/syslog.conf').with_content(expected_content)
          }
          it {
            is_expected.to contain_rsyslog__rule__drop('audispd').with_rule(%r(\$programname == 'audispd'))
          }
        end

        context "when allow audit messages" do
          let(:params) {{
            :drop_audit_logs => false
          }}

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_file('/etc/audisp/plugins.d/syslog.conf').with_content(%r(active = yes))
          }
          it { is_expected.to_not contain_rsyslog__rule__drop('audispd') }
        end

        context "when syslog priority is invalid" do
          # appropriate priority for /usr/bin/logger, but not audisp
          let(:params) {{
            :priority => 'warn'
          }}
          it { is_expected.to_not compile.with_all_deps }
        end

        context "when syslog facility is invalid" do
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
