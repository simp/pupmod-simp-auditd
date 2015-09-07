require 'spec_helper'

describe 'auditd' do
  context 'RHEL6' do
    let(:facts) {{
      :fqdn => 'test.host.net',
      :hardwaremodel => 'x86_64',
      :operatingsystem => 'RedHat',
      :operatingsystemmajrelease => '6',
      :apache_version => '2.4',
      :grub_version => '0.9',
      :uid_min => '500'
    }}

    let(:params) {{
      :buffer_size => '12345',
      :root_audit_level => 'basic',
      :num_logs => '4'
    }}

    it { should compile.with_all_deps }
    it { should create_class('auditd::audisp') }
    it {
      should create_auditd__add_rules('init.d_auditd').with({
        :content => /-k audit-logs/
      })
    }
    it {
      should create_auditd__add_rules('rotated_audit_logs').with({
        :content => /-w \/var\/log\/audit\.log\.#{params[:num_logs]} -p rwa -k audit-logs/
      })
    }
    it {
      should create_concat_fragment('auditd+head').with({
        :content => /-b #{params[:buffer_size]}/
      })
    }
    it { should create_file('/etc/audit/auditd.conf') }
    it { should create_file('/var/log/audit').with({ :mode => '0700' }) }
    it { should create_service('auditd').with({ :ensure => 'running' }) }

    context 'aggressive' do
      let(:params) {{
        :buffer_size => '12345',
        :root_audit_level => 'aggressive',
        :num_logs => '4'
      }}

      it {
        should create_concat_fragment('auditd+head').with({
          :content => /-b 32788/
        })
      }
    end

    context 'insane' do
      let(:params) {{
        :buffer_size => '12345',
        :root_audit_level => 'insane',
        :num_logs => '4'
      }}

      it {
        should create_concat_fragment('auditd+head').with({
          :content => /-b 65576/
        })
      }
    end

    context 'insane_with_override' do
      let(:params) {{
        :buffer_size => '65588',
        :root_audit_level => 'insane',
        :num_logs => '4'
      }}

      it {
        should create_concat_fragment('auditd+head').with({
          :content => /-b #{params[:buffer_size]}/
        })
      }
    end
  end

  context 'RHEL7' do
    let(:facts) {{
      :fqdn => 'test.host.net',
      :hardwaremodel => 'x86_64',
      :operatingsystem => 'RedHat',
      :operatingsystemmajrelease => '7',
      :apache_version => '2.4',
      :grub_version => '2.0~beta',
      :uid_min => '1000'
    }}

    let(:params) {{
      :buffer_size => '12345',
      :root_audit_level => 'basic',
      :num_logs => '4'
    }}

    it { should compile.with_all_deps }
    it { should create_class('auditd::audisp') }
    it {
      should create_auditd__add_rules('init.d_auditd').with({
        :content => /-k audit-logs/
      })
    }
    it {
      should create_auditd__add_rules('rotated_audit_logs').with({
        :content => /-w \/var\/log\/audit\.log\.#{params[:num_logs]} -p rwa -k audit-logs/
      })
    }
    it { should create_file('/etc/audit/rules.d/00_head.rules').with_content(/-b #{params[:buffer_size]}/) }
    it { should create_file('/etc/audit/auditd.conf') }
    it { should create_file('/var/log/audit').with({ :mode => '0700' }) }
    it { should create_service('auditd').with({ :ensure => 'running' }) }

    context 'aggressive' do
      let(:params) {{
        :buffer_size => '12345',
        :root_audit_level => 'aggressive',
        :num_logs => '4'
      }}

      it { should create_file('/etc/audit/rules.d/00_head.rules').with_content(/-b 32788/) }
    end

    context 'insane' do
      let(:params) {{
        :buffer_size => '12345',
        :root_audit_level => 'insane',
        :num_logs => '4'
      }}

      it { should create_file('/etc/audit/rules.d/00_head.rules').with_content(/-b 65576/) }
    end

    context 'insane_with_override' do
      let(:params) {{
        :buffer_size => '65588',
        :root_audit_level => 'insane',
        :num_logs => '4'
      }}

      it { should create_file('/etc/audit/rules.d/00_head.rules').with_content(/-b #{params[:buffer_size]}/) }
    end
  end
end
