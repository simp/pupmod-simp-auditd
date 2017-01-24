require 'spec_helper'

describe 'auditd::rule' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:title) { 'test' }
        let(:params) {{ :content => 'rspec_audit_message' }}
        let(:pre_condition) {
          'include ::auditd'
        }

        let(:facts) do
          if ['RedHat','CentOS'].include?(facts[:operatingsystem]) && facts[:operatingsystemmajrelease].to_s < '7'
            facts[:apache_version] = '2.2'
            facts[:grub_version] = '0.9'
          else
            facts[:apache_version] = '2.4'
            facts[:grub_version] = '2.0~beta'
          end

          facts
        end

        it { is_expected.to compile.with_all_deps }

        context "without any parameters" do
          it {
            is_expected.to contain_file("/etc/audit/rules.d/75.#{title}.rules").with_content(%r(#{params[:content]}))
          }
        end

        context 'with :content containing extra whitespace' do

          let(:title){ 'test' }

          # :content string mocks a common pattern of declaring readable auditd rules.
          let(:params) {{
            :content => '
              -a always,exit -F dir=${confdir} -F uid!=puppet -p wa -k Puppet_Config
              -a always,exit -F dir=${logdir} -F uid!=puppet -p wa -k Puppet_Log
              -a always,exit -F dir=${rundir} -F uid!=puppet -p wa -k Puppet_Run
              -a always,exit -F dir=${ssldir} -F uid!=puppet -p wa -k Puppet_SSL
            '
          }}

          it {
           is_expected.to compile.with_all_deps
           is_expected.to create_file("/etc/audit/rules.d/75.#{title}.rules").with({ :content => /^-a always,exit -F dir=/ })
           is_expected.to create_file("/etc/audit/rules.d/75.#{title}.rules").without({ :content => /^[^-]/ })
          }
        end

        context 'when set to :first' do
          let(:params) {{
            :first => true,
            :content => 'audit stuff'
          }}

          it {
            is_expected.to compile.with_all_deps
            is_expected.to contain_file("/etc/audit/rules.d/10.#{title}.rules").with_content(%r(#{params[:content]}))
          }
        end

        context 'when set to :absolute :first' do
          let(:params) {{
            :first => true,
            :absolute => true,
            :content => 'audit stuff'
          }}

          it {
            is_expected.to compile.with_all_deps
            is_expected.to contain_file("/etc/audit/rules.d/01.#{title}.rules").with_content(%r(#{params[:content]}))
          }
        end

        context 'when set to :prepend' do
          let(:params) {{
            :prepend => true,
            :content => 'audit stuff'
          }}

          it {
            is_expected.to compile.with_all_deps
            is_expected.to contain_file("/etc/audit/rules.d/00.#{title}.rules").with_content(%r(#{params[:content]}))
          }
        end
      end
    end
  end
end
