require 'spec_helper'

# auditd::config::audisp is public, so a profile can declare it before
# auditd::config has been evaluated. It tests the version with
# auditd::auditd2(), which reads only the fact.
describe 'auditd::config::audisp' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      context 'declared on its own with auditd 3' do
        let(:facts) { os_facts.merge(auditd_version: '3.0.7') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_file('/etc/audisp/audispd.conf') }
      end

      context 'declared on its own without the auditd_version fact' do
        let(:facts) { os_facts.reject { |k, _v| [:auditd_version, :auditd_major_version, :simplib__auditd].include?(k) } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_file('/etc/audisp/audispd.conf') }
      end

      context 'with auditd 2' do
        let(:pre_condition) { 'include auditd' }
        let(:facts) { os_facts.merge(auditd_version: '2.8.5') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/audisp/audispd.conf') }
      end
    end
  end
end
