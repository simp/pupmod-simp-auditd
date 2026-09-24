require 'spec_helper'

# auditd::config::rule_settings is private, so it is tested through auditd.
describe 'auditd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:settings) { '/etc/audit/rules.d/puppet_auditd.rules' }

      context 'with default parameters' do
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('auditd::config::rule_settings') }
        it { is_expected.not_to contain_file(settings) }
      end

      # One enforced setting takes effect on its own: no profile, no purge,
      # and nothing else in rules.d is touched.
      context 'with only failure_mode => 2' do
        let(:params) { { failure_mode: 2 } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file(settings).with(ensure: 'file', content: nil) }
        it { is_expected.to contain_file_line('rule settings failure_mode').with(path: settings, line: '-f 2', match: '^-f\s') }
        it { is_expected.not_to contain_file('/etc/audit/rules.d') }
        it { is_expected.not_to contain_file('/etc/audit/rules.d/00_head.rules') }
        it { is_expected.not_to contain_file_line('rule settings packaged -b') }

        it 'manages nothing else in rules.d' do
          managed = catalogue.resources
                             .select { |r| ['File', 'File_line'].include?(r.type) }
                             .map(&:to_s)
                             .sort
          expect(managed).to eq(["File[#{settings}]", 'File_line[rule settings failure_mode]'])
        end
      end

      # The floor sizes the backlog for the profile rules the heavier levels
      # generate, so without a profile there is nothing to size it for.
      context "with root_audit_level => 'aggressive' and no profile" do
        let(:params) { { root_audit_level: 'aggressive' } }

        it { is_expected.not_to contain_file(settings) }
        it { is_expected.not_to contain_file_line('rule settings buffer_size') }
      end

      context "with root_audit_level => 'aggressive' and the simp profile" do
        let(:params) { { root_audit_level: 'aggressive', default_audit_profiles: ['simp'] } }

        it { is_expected.to contain_file_line('rule settings buffer_size').with(path: settings, line: '-b 32788') }
      end
    end
  end
end
