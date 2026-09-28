require 'spec_helper'

describe 'auditd::rule_match' do
  it 'escapes regex metacharacters and accepts either key form' do
    is_expected.to run.with_params('-w /etc/yum.conf -p wa').and_return('^-w /etc/yum\.conf -p wa (?:-k |-F key=)')
  end

  it 'matches any auid>= value' do
    is_expected.to run.with_params('-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset')
                      .and_return('^-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=\d+ -F auid!=unset (?:-k |-F key=)')
  end

  it 'matches any -S list when asked' do
    is_expected.to run.with_params('-a always,exit -F arch=b64 -F auid!=0 -F uid=0 -S capset,mknod', true)
                      .and_return('^-a always,exit -F arch=b64 -F auid!=0 -F uid=0 -S \S+ (?:-k |-F key=)')
  end

  it 'keeps the -S list otherwise' do
    is_expected.to run.with_params('-a always,exit -F arch=b64 -S chown,fchown').and_return('^-a always,exit -F arch=b64 -S chown,fchown (?:-k |-F key=)')
  end

  it 'matches only the given key when asked' do
    is_expected.to run.with_params('-w /usr/bin/at -p x', false, 'setuid/setgid').and_return('^-w /usr/bin/at -p x (?:-k |-F key=)setuid/setgid$')
  end

  context 'matching real rules' do
    let(:function) { find_function }
    let(:pattern) { Regexp.new(function.execute('-a always,exit -F arch=b64 -S ptrace')) }

    it 'matches the rule under either key form' do
      expect(pattern).to match('-a always,exit -F arch=b64 -S ptrace -k paranoid')
      expect(pattern).to match('-a always,exit -F arch=b64 -S ptrace -F key=paranoid')
    end

    it 'does not match the same rule under another key when given one' do
      keyed = Regexp.new(function.execute('-a always,exit -F arch=b64 -S ptrace', false, 'paranoid'))

      expect(keyed).to match('-a always,exit -F arch=b64 -S ptrace -F key=paranoid')
      expect(keyed).not_to match('-a always,exit -F arch=b64 -S ptrace -F key=paranoid2')
    end

    it 'does not match a longer rule that starts the same way' do
      expect(pattern).not_to match('-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k paranoid_code_injection')
    end
  end
end
