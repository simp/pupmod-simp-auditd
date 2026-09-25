require 'spec_helper'

describe 'auditd::list_entries' do
  it { is_expected.to run.with_params(['a', 'b']).and_return('a' => 'present', 'b' => 'present') }
  it { is_expected.to run.with_params([]).and_return({}) }
  it { is_expected.to run.with_params('a' => {}, 'b' => { 'ensure' => 'absent' }).and_return('a' => 'present', 'b' => 'absent') }
  it { is_expected.to run.with_params('a' => { 'ensure' => 'bogus' }).and_raise_error(ArgumentError) }
end
