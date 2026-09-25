require 'spec_helper'

# This used to be an implementation detail: auditd::space_left defaulted to
# auditd::calculate_space_left($admin_space_left), so the only coverage it had
# was whatever init_spec.rb asserted about that default. The default is gone
# (the catalogue now fails rather than guess a threshold), and the class
# documentation points sites at this function instead, which makes it public
# API and gives it its own spec.
describe 'auditd::calculate_space_left' do
  it 'adds 30 to an Integer' do
    is_expected.to run.with_params(50).and_return(80)
  end

  it 'adds 30 to zero' do
    is_expected.to run.with_params(0).and_return(30)
  end

  it 'adds one point to a percentage, and keeps it a percentage' do
    is_expected.to run.with_params('20%').and_return('21%')
  end

  # auditd reads space_left as a percentage of the free space on the log
  # partition, so 100% is a legal, if useless, input. It is the boundary where
  # the result stops being a meaningful percentage, which is the site's
  # problem and not this function's: it is documented as arithmetic.
  it 'does not clamp a percentage at 100' do
    is_expected.to run.with_params('100%').and_return('101%')
  end

  # The parameter type is the whole of the input validation, so these assert
  # that it is tight enough to be the only validation there is.
  it 'rejects a negative Integer' do
    is_expected.to run.with_params(-1).and_raise_error(ArgumentError, %r{parameter 'admin_space_left'})
  end

  it 'rejects a bare numeric String' do
    is_expected.to run.with_params('50').and_raise_error(ArgumentError, %r{parameter 'admin_space_left'})
  end

  it 'rejects a percentage with trailing text' do
    is_expected.to run.with_params('20% free').and_raise_error(ArgumentError, %r{parameter 'admin_space_left'})
  end
end
