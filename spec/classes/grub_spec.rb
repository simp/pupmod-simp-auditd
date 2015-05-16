require 'spec_helper'

describe 'auditd::grub' do
  let(:facts) {{
    :fqdn => 'test.host.net',
    :hardwaremodel => 'x86_64',
    :operatingsystem => 'RedHat',
    :lsbmajdistrelease => '6',
    :apache_version => '2.4',
    :grub_version => '0.9',
    :uid_min => '500'
  }}

  ['present','absent'].each do |en_val|
    context "ensure_#{en_val}" do
      let(:params){{ :ensure => en_val }}

      param_map = {
        'present' => '1',
        'absent'  => '0'
      }

      it { should compile.with_all_deps }
      it { should create_reboot_notify('audit').that_subscribes_to('Kernel_parameter[audit]') }
      it { should create_kernel_parameter('audit').with_value(param_map[params[:ensure]]) }
    end
  end
end
