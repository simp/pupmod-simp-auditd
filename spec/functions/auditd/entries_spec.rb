require 'spec_helper'

describe 'auditd::entries' do
  it { is_expected.to run.with_params({}).and_return({}) }
  it { is_expected.to run.with_params({ 'a' => {} }).and_return('a' => 'present') }
  it { is_expected.to run.with_params({ 'a' => { 'ensure' => 'present' }, 'b' => { 'ensure' => 'absent' } }).and_return('a' => 'present', 'b' => 'absent') }
  it { is_expected.to run.with_params({ 'a' => {} }, ['b']).and_return('a' => 'present', 'b' => 'present') }
  it { is_expected.to run.with_params({ 'a' => {}, 'b' => {} }, ['--b']).and_return('a' => 'present', 'b' => 'absent') }
  it { is_expected.to run.with_params({ 'a' => { 'ensure' => 'absent' } }, ['a']).and_return('a' => 'present') }
  it { is_expected.to run.with_params({ 'a' => 'present' }).and_raise_error(ArgumentError) }
  it { is_expected.to run.with_params({ 'a' => { 'ensrue' => 'absent' } }).and_raise_error(ArgumentError) }
  it { is_expected.to run.with_params({ 'a' => { 'ensure' => 'absnet' } }).and_raise_error(ArgumentError) }
end
