require 'spec_helper'

describe 'auditd::entries' do
  it { is_expected.to run.with_params({}).and_return({}) }
  it { is_expected.to run.with_params({ 'a' => 'present', 'b' => 'absent' }).and_return('a' => 'present', 'b' => 'absent') }
  it { is_expected.to run.with_params({ 'a' => 'present' }, ['b']).and_return('a' => 'present', 'b' => 'present') }
  it { is_expected.to run.with_params({ 'a' => 'present', 'b' => 'present' }, ['--b']).and_return('a' => 'present', 'b' => 'absent') }
  it { is_expected.to run.with_params({ 'a' => 'absent' }, ['a']).and_return('a' => 'present') }
  it { is_expected.to run.with_params({ 'a' => 'bogus' }).and_raise_error(ArgumentError) }
end
