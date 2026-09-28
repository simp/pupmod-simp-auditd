require 'spec_helper'

describe 'auditd_state' do
  let(:auditctl) { '/usr/sbin/auditctl' }

  def status(enabled)
    <<~EOM
      enabled #{enabled}
      failure 1
      pid 1234
      rate_limit 0
      backlog_limit 8192
      lost 0
      backlog 0
      loginuid_immutable 0 unlocked
    EOM
  end

  before :each do
    Facter.clear
    allow(Facter.fact(:kernel)).to receive(:value).and_return('Linux')
    allow(Facter).to receive(:value).and_call_original
    allow(Facter::Core::Execution).to receive(:which).and_call_original
    allow(Facter::Core::Execution).to receive(:which).with('auditctl').and_return(auditctl)
    allow(Facter::Core::Execution).to receive(:which).with('ps').and_return('/usr/bin/ps')
    allow(Facter::Core::Execution).to receive(:execute).and_call_original
    allow(Facter::Core::Execution).to receive(:execute).with("#{auditctl} -v", on_fail: nil).and_return('auditctl version 3.1.2')
    allow(Facter::Core::Execution).to receive(:execute).with('/usr/bin/ps -e', on_fail: nil).and_return("    1 ?        00:00:01 systemd\n  812 ?        00:00:00 auditd\n")
  end

  context 'with auditing enabled' do
    before(:each) { allow(Facter::Core::Execution).to receive(:execute).with("#{auditctl} -s", on_fail: nil).and_return(status(1)) }

    it 'reports the auditctl status keys, the version and the derived state' do
      expect(Facter.fact(:auditd_state).value).to eq(
        'enabled'            => 1,
        'failure'            => 1,
        'pid'                => 1234,
        'rate_limit'         => 0,
        'backlog_limit'      => 8192,
        'lost'               => 0,
        'backlog'            => 0,
        'loginuid_immutable' => '0 unlocked',
        'version'            => '3.1.2',
        'immutable'          => false,
        'kernel_enforcing'   => true,
        'enforcing'          => true,
      )
    end

    it 'is not enforcing when auditd is not running' do
      allow(Facter::Core::Execution).to receive(:execute).with('/usr/bin/ps -e', on_fail: nil).and_return("    1 ?        00:00:01 systemd\n")
      expect(Facter.fact(:auditd_state).value).to include('kernel_enforcing' => true, 'enforcing' => false)
    end
  end

  context 'with an immutable rule set' do
    before(:each) { allow(Facter::Core::Execution).to receive(:execute).with("#{auditctl} -s", on_fail: nil).and_return(status(2)) }

    it 'keeps the raw flag and reports it immutable and enforcing' do
      expect(Facter.fact(:auditd_state).value).to include(
        'enabled'          => 2,
        'immutable'        => true,
        'kernel_enforcing' => true,
        'enforcing'        => true,
      )
    end
  end

  context 'with auditing disabled' do
    before(:each) { allow(Facter::Core::Execution).to receive(:execute).with("#{auditctl} -s", on_fail: nil).and_return(status(0)) }

    it 'takes kernel_enforcing from the kernel command line' do
      allow(Facter).to receive(:value).with('cmdline').and_return('audit' => '1')
      expect(Facter.fact(:auditd_state).value).to include('enabled' => 0, 'immutable' => false, 'kernel_enforcing' => true, 'enforcing' => false)
    end

    it 'is not kernel_enforcing without audit=1' do
      allow(Facter).to receive(:value).with('cmdline').and_return({})
      expect(Facter.fact(:auditd_state).value).to include('kernel_enforcing' => false, 'enforcing' => false)
    end
  end

  # auditctl -s refuses to run for non-root users.
  context 'when the status cannot be read' do
    before(:each) { allow(Facter::Core::Execution).to receive(:execute).with("#{auditctl} -s", on_fail: nil).and_return(nil) }

    it 'still reports the version, and nothing it cannot prove' do
      allow(Facter).to receive(:value).with('cmdline').and_return({})
      expect(Facter.fact(:auditd_state).value).to eq(
        'version'          => '3.1.2',
        'immutable'        => false,
        'kernel_enforcing' => false,
        'enforcing'        => false,
      )
    end
  end

  context 'without auditctl' do
    let(:auditctl) { nil }

    it { expect(Facter.fact(:auditd_state).value).to be_nil }
  end
end
