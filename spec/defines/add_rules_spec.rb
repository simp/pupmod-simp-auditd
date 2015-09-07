require 'spec_helper'

describe 'auditd::add_rules' do
  let(:facts) {{
    :fqdn => 'test.host.net',
    :hardwaremodel => 'x86_64',
    :operatingsystem => 'RedHat',
    :operatingsystemmajrelease => '6',
    :apache_version => '2.4',
    :grub_version => '0.9',
    :uid_min => '500'
  }}

  context 'base' do
    let(:title){ 'test' }

    let(:params) {{
      :content => 'foobar'
    }}

    it { should compile.with_all_deps }
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
     should compile.with_all_deps
     should create_concat_fragment('auditd+75.test.rules.post').with({ :content => /^-a always,exit -F dir=/ })
     should create_concat_fragment('auditd+75.test.rules.post').without({ :content => /^[^-]/ })
    }
  end
end
