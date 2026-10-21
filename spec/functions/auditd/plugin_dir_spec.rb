require 'spec_helper'

describe 'auditd::plugin_dir' do
  context 'without a path' do
    context 'with auditd 3' do
      let(:facts) { { auditd_version: '3.1.5' } }

      it { is_expected.to run.with_params.and_return('/etc/audit/plugins.d') }
    end

    context 'with auditd 2' do
      let(:facts) { { auditd_version: '2.8.5' } }

      it { is_expected.to run.with_params.and_return('/etc/audisp/plugins.d') }
    end

    context 'without the auditd_version fact' do
      let(:facts) { {} }

      it { is_expected.to run.with_params(nil).and_return('/etc/audit/plugins.d') }
    end
  end

  # Normalized the way Puppet normalizes a File's path, so another spelling of
  # one directory is not a second File title for it.
  context 'with a path' do
    it { is_expected.to run.with_params('/opt/audit/plugins.d').and_return('/opt/audit/plugins.d') }
    it { is_expected.to run.with_params('/etc/audit/plugins.d/').and_return('/etc/audit/plugins.d') }
    it { is_expected.to run.with_params('/etc/audit//plugins.d//').and_return('/etc/audit/plugins.d') }
    it { is_expected.to run.with_params('//etc/audit/plugins.d').and_return('/etc/audit/plugins.d') }
    it { is_expected.to run.with_params('/').and_return('/') }
    it { is_expected.to run.with_params('relative/path').and_raise_error(%r{expects a Stdlib::Absolutepath}) }
  end
end
