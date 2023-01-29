require 'spec_helper'

describe 'auditd' do
  shared_examples_for 'a structured module' do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('auditd') }
    it { is_expected.to contain_class('auditd') }
    it { is_expected.to contain_class('auditd::install').that_comes_before('Class[auditd::config]') }
    it { is_expected.to contain_class('auditd::config') }
    it { is_expected.to contain_class('auditd::service').that_subscribes_to('Class[auditd::config]') }
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:base_facts) do
          os_facts.merge(
            {
              # Oldest version shipping with EL7
              :auditd_version => '2.4.1',
              :simplib__auditd => {
                'enabled' => true,
                'kernel_enforcing' => true
              }
            }
          )
        end

        let(:facts) do
          base_facts
        end

        context 'auditd with default parameters' do
          let(:params) {{ }}
          it_behaves_like 'a structured module'
          it {
            is_expected.to contain_service('auditd').with({
              :ensure  => true,
              :enable  => true,
              :start   => "/sbin/service auditd start",
              :stop    => "/sbin/service auditd stop",
              :restart => "/sbin/service auditd restart"
            })
          }
          it { is_expected.to contain_class('auditd::install').that_comes_before('Class[auditd::config::grub]') }
          it { is_expected.to contain_class('auditd::config::grub').with_enable(true) }
          it { is_expected.to_not contain_class('auditd::config::logging') }

          context 'on a host without grub' do
            let(:facts) { super().merge(grub_version: nil) }

            it { is_expected.to contain_class('auditd::install') }
            it { is_expected.not_to contain_class('auditd::install').that_comes_before('Class[auditd::config::grub]') }
            it { is_expected.not_to contain_class('auditd::config::grub') }
          end
        end

        context 'auditd with space_left < admin_space_left' do
          let(:params) {{
            :space_left       => 20,
            :admin_space_left => 25
          }}

          it { is_expected.to compile.and_raise_error(/Auditd requires \$space_left to be greater than \$admin_space_left, otherwise it will not start/) }
        end

        context 'with space_left as a percentage' do
          let(:params) do
            {
              :space_left => '20%'
            }
          end

          it { is_expected.to compile.and_raise_error(/cannot contain "%"/) }
        end

        context 'with space_left as a percentage' do
          let(:params) do
            {
              :admin_space_left => '20%'
            }
          end

          it { is_expected.to compile.and_raise_error(/cannot contain "%"/) }
        end

        context 'auditd 2.8.5' do
          context 'with space_left as a percentage' do
            let(:facts) do
              base_facts.merge({
                :auditd_version => '2.8.5'
              })
            end

            let(:params) do
              {
                :space_left => '20%'
              }
            end

            it { is_expected.to compile.with_all_deps }
          end

          context 'with admin_space_left as a percentage' do
            let(:facts) do
              base_facts.merge({
                :auditd_version => '2.8.5'
              })
            end

            let(:params) do
              {
                :admin_space_left => '20%'
              }
            end

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to contain_class('auditd').with_space_left('21%') }
          end
        end

        context 'auditd with auditing disabled' do
          let(:params) {{
            :enable => false
          }}

          it { is_expected.to contain_class('auditd::config::grub').with_enable(false) }
          it { is_expected.to_not contain_class('auditd::install') }
          it { is_expected.to_not contain_class('auditd::config') }
          it { is_expected.to contain_class('auditd::service') }
        end
      end
    end
  end

  context 'unsupported operating system' do
    describe 'auditd without any parameters on Solaris/Nexenta' do
      let(:facts) {
        {
          :os => {
            'name' => 'Solaris'
          }
        }
      }

     it { expect { is_expected.to contain_package('auditd') }.to raise_error(Puppet::Error) }
    end
  end
end
