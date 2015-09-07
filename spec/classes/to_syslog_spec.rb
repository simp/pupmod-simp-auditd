require 'spec_helper'

describe 'auditd::to_syslog' do
  let(:facts) {{
    :fqdn => 'test.host.net',
    :hardwaremodel => 'x86_64',
    :operatingsystem => 'RedHat',
    :operatingsystemmajrelease => '6',
    :apache_version => '2.4',
    :grub_version => '0.9',
    :uid_min => '500',
    :interfaces => 'eth0'
  }}

  it { should compile.with_all_deps }
  it { should create_file('/etc/audisp/plugins.d/syslog.conf') }

  context 'offload_logs' do
    let(:params){{
      :log_servers => ['foo.bar.baz','foo2.bar.baz'],
    }}

    it { should compile.with_all_deps }
    it { should create_class('rsyslog') }
    it {
      should create_rsyslog__rule__drop('audispd').with({
        :rule => "if \$programname == 'audispd'"
      })
    }
  end
end
