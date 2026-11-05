require 'spec_helper'

describe 'auditd_auditctl_cmd' do
  before :each do
    Facter.clear
    allow(Facter.fact(:kernel)).to receive(:value).and_return('Linux')
    allow(Facter::Core::Execution).to receive(:which).and_call_original
  end

  it 'returns the path to auditctl' do
    allow(Facter::Core::Execution).to receive(:which).with('auditctl').and_return('/usr/sbin/auditctl')
    expect(Facter.fact(:auditd_auditctl_cmd).value).to eq('/usr/sbin/auditctl')
  end

  it 'does not use the deprecated Facter::Util::Resolution.which' do
    allow(Facter::Core::Execution).to receive(:which).with('auditctl').and_return('/usr/sbin/auditctl')
    expect(Facter::Util::Resolution).not_to receive(:which).with('auditctl')
    Facter.fact(:auditd_auditctl_cmd).value
  end

  it 'is nil without auditctl' do
    allow(Facter::Core::Execution).to receive(:which).with('auditctl').and_return(nil)
    expect(Facter.fact(:auditd_auditctl_cmd).value).to be_nil
  end
end
