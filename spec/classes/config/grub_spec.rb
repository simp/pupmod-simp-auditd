require 'spec_helper'

describe 'auditd::config::grub' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          if ['RedHat', 'CentOS'].include?(facts[:os][:name]) && facts[:os][:release][:major].to_i < 7
            facts[:apache_version] = '2.2'
            facts[:grub_version] = '0.9'
          else
            facts[:apache_version] = '2.4'
            facts[:grub_version] = '2.0~beta'
          end
          unless facts[:auditd_major_version]
            facts[:auditd_major_version] = if facts[:os][:release][:major].to_i < 8
                                             '2'
                                           else
                                             '3'
                                           end
          end
          facts
        end

        it { is_expected.to compile.with_all_deps }

        context 'with augeasproviders_grub >= 6.0.0' do
          context 'without any parameters' do
            let(:params) { { augeasproviders_grub_version: '6.0.0' } }

            it { is_expected.to contain_kernel_parameter('audit:all').with_value('1') }
            it {
              is_expected.to contain_reboot_notify('audit:all').that_subscribes_to('Kernel_parameter[audit:all]')
            }
          end

          context 'when disabled' do
            let(:params) do
              {
                enable: false,
                augeasproviders_grub_version: '6.0.0',
              }
            end

            it { is_expected.to contain_kernel_parameter('audit:all').with_value('0') }
            it {
              is_expected.to contain_reboot_notify('audit:all').that_subscribes_to('Kernel_parameter[audit:all]')
            }
          end
        end

        context 'with augeasproviders_grub < 6.0.0' do
          context 'without any parameters' do
            let(:params) { { augeasproviders_grub_version: '5.0.0' } }

            it { is_expected.to contain_kernel_parameter('audit').with_value('1') }
            it {
              is_expected.to contain_reboot_notify('audit').that_subscribes_to('Kernel_parameter[audit]')
            }
          end

          context 'when disabled' do
            let(:params) do
              {
                enable: false,
                augeasproviders_grub_version: '5.0.0',
              }
            end

            it { is_expected.to contain_kernel_parameter('audit').with_value('0') }
            it {
              is_expected.to contain_reboot_notify('audit').that_subscribes_to('Kernel_parameter[audit]')
            }
          end
        end
      end
    end
  end
end
