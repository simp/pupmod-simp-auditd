require 'spec_helper'

describe 'auditd::rule' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:title) { 'test' }
        let(:params) { { content: 'rspec_audit_message' } }
        let(:facts) do
          _facts = Marshal.load(Marshal.dump(os_facts))
          unless _facts[:auditd_major_version]
            _facts[:auditd_major_version] = if _facts[:os][:release][:major] < '8'
                                              '2'
                                            else
                                              '3'
                                            end
          end

          _facts
        end

        it { is_expected.to compile.with_all_deps }

        context 'without any parameters' do
          it {
            is_expected.to contain_class('auditd')
            is_expected.to contain_file("/etc/audit/rules.d/75.#{title}.rules").with_content(%r{#{params[:content]}})
          }
        end

        context 'when :content is an Array' do
          let(:params) do
            {
              content: [
                '-a always,exit -F dir=${confdir} -F uid!=puppet -p wa -k Puppet_Config',
                '-a always,exit -F dir=${logdir} -F uid!=puppet -p wa -k Puppet_Log',
                '-a always,exit -F dir=${rundir} -F uid!=puppet -p wa -k Puppet_Run',
                '-a always,exit -F dir=${ssldir} -F uid!=puppet -p wa -k Puppet_SSL',
              ]
            }
          end

          it {
            is_expected.to compile.with_all_deps
            is_expected.to create_file("/etc/audit/rules.d/75.#{title}.rules").with_content(%r{^-a always,exit -F dir=})
            is_expected.to create_file("/etc/audit/rules.d/75.#{title}.rules").without_content(%r{^[^-]})
          }
        end

        context 'with :content containing extra whitespace' do
          # :content string mocks a common pattern of declaring readable auditd rules.
          let(:params) do
            {
              content: '
              -a always,exit -F dir=${confdir} -F uid!=puppet -p wa -k Puppet_Config
              -a always,exit -F dir=${logdir} -F uid!=puppet -p wa -k Puppet_Log
              -a always,exit -F dir=${rundir} -F uid!=puppet -p wa -k Puppet_Run
              -a always,exit -F dir=${ssldir} -F uid!=puppet -p wa -k Puppet_SSL
            '
            }
          end

          it {
            is_expected.to compile.with_all_deps
            is_expected.to create_file("/etc/audit/rules.d/75.#{title}.rules").with_content(%r{^-a always,exit -F dir=})
            is_expected.to create_file("/etc/audit/rules.d/75.#{title}.rules").without_content(%r{^[^-]})
          }
        end

        context 'with :order specified' do
          let(:params) do
            {
              order: '10',
           content: '-a always,exit -F dir=${confdir} -F uid!=puppet -p wa -k Puppet_Config'
            }
          end

          it {
            is_expected.to compile.with_all_deps
            is_expected.to create_file("/etc/audit/rules.d/#{params[:order]}.#{title}.rules").with_content(%r{#{Regexp.escape(params[:content])}})
          }
        end

        context 'when set to :first' do
          let(:params) do
            {
              first: true,
           content: 'audit stuff'
            }
          end

          it {
            is_expected.to compile.with_all_deps
            is_expected.to contain_file("/etc/audit/rules.d/10.#{title}.rules").with_content(%r{#{params[:content]}})
          }
        end

        context 'when set to :absolute :first' do
          let(:params) do
            {
              first: true,
           absolute: true,
           content: 'audit stuff'
            }
          end

          it {
            is_expected.to compile.with_all_deps
            is_expected.to contain_file("/etc/audit/rules.d/01.#{title}.rules").with_content(%r{#{params[:content]}})
          }
        end

        context 'when set to :prepend' do
          let(:params) do
            {
              prepend: true,
           content: 'audit stuff'
            }
          end

          it {
            is_expected.to compile.with_all_deps
            is_expected.to contain_file("/etc/audit/rules.d/00.#{title}.rules").with_content(%r{#{params[:content]}})
          }
        end
      end
    end
  end
end
