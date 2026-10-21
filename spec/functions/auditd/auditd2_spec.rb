require 'spec_helper'

describe 'auditd::auditd2' do
  context 'with auditd 2' do
    let(:facts) { { auditd_version: '2.8.5' } }

    it { is_expected.to run.with_params.and_return(true) }
  end

  context 'with auditd 3' do
    let(:facts) { { auditd_version: '3.1.5' } }

    it { is_expected.to run.with_params.and_return(false) }
  end

  # The fact needs auditctl, which a first run on EL10 installs in the same
  # run; every supported release ships audit 3 or later.
  context 'without the auditd_version fact' do
    let(:facts) { {} }

    it { is_expected.to run.with_params.and_return(false) }
  end
end
