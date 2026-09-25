require 'spec_helper'

describe 'auditd_version' do
  before :each do
    Facter.clear
    allow(Facter.fact(:kernel)).to receive(:value).and_return('Linux')
  end

  it 'comes from auditd_state' do
    allow(Facter.fact(:auditd_state)).to receive(:value).and_return('version' => '3.1.2')
    expect(Facter.fact(:auditd_version).value).to eq('3.1.2')
    expect(Facter.fact(:auditd_major_version).value).to eq('3')
  end

  it 'is nil without auditd_state' do
    allow(Facter.fact(:auditd_state)).to receive(:value).and_return(nil)
    expect(Facter.fact(:auditd_version).value).to be_nil
  end
end
