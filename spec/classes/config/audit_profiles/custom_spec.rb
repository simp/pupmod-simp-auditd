require 'spec_helper'

describe 'auditd::config::audit_profiles::custom' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      let(:common_pre_condition) do
        <<-EOM
          function assert_private() { }

          class auditd::config (
            $profiles = ['custom'],
            $config_file_mode = '0600'
          ){}
          include auditd::config
        EOM
      end

      let(:pre_condition) { common_pre_condition }

      context 'with rules specified' do
        let(:params) do
          {
            rules: [
              'First Rule',
              'Second Rule',
            ]
          }
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/audit/rules.d/50_00_custom_base.rules').with_content(params[:rules].join("\n") + "\n") }
      end

      context 'when using templates' do
        context 'with EPP template specified' do
          let(:params) do
            {
              template: 'foo/bar.epp'
            }
          end

          let(:pre_condition) do
            <<-EOM
              #{common_pre_condition}

              function epp($arg) >> String { 'EPP!' }
            EOM
          end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_file('/etc/audit/rules.d/50_00_custom_base.rules').with_content("EPP!\n") }
        end

        context 'with ERB template specified' do
          let(:params) do
            {
              template: 'foo/bar.erb'
            }
          end

          let(:pre_condition) do
            <<-EOM
              #{common_pre_condition}

              function template($arg) >> String { 'ERB!' }
            EOM
          end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_file('/etc/audit/rules.d/50_00_custom_base.rules').with_content("ERB!\n") }
        end

        context 'with an invalid template name specified' do
          let(:params) do
            {
              template: 'foo/bar.bad'
            }
          end

          it { expect { is_expected.to compile.with_all_deps }.to raise_error(%r{must end with}) }
        end
      end

      context 'with invalid options' do
        it 'requires $rules or $template' do
          expect { is_expected.to compile.with_all_deps }.to raise_error(%r{must specify either})
        end

        context 'with both $rules and $template' do
          let(:params) do
            {
              rules: ['RULEZ'],
           template: 'foo/bar.epp'
            }
          end

          it { expect { is_expected.to compile.with_all_deps }.to raise_error(%r{may not specify}) }
        end
      end

      context 'with other profiles specified' do
        let(:pre_condition) do
          <<-EOM
            function assert_private() { }

            class auditd::config (
              $profiles = ['simp', 'custom', 'stig'],
              $config_file_mode = '0600'
            ){}
            include auditd::config
          EOM
        end

        let(:params) do
          {
            rules: [
              'First Rule',
              'Second Rule',
            ]
          }
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/audit/rules.d/50_01_custom_base.rules').with_content(params[:rules].join("\n") + "\n") }
      end
    end
  end
end
