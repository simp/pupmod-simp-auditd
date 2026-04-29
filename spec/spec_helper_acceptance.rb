require 'beaker-rspec'
require 'tmpdir'
require 'yaml'
require 'simp/beaker_helpers'
include Simp::BeakerHelpers

unless ENV['BEAKER_provision'] == 'no'
  hosts.each do |host|
    # Install Puppet
    if host.is_pe?
      install_pe
    else
      install_puppet
    end
  end
end

RSpec.configure do |c|
  # ensure that environment OS is ready on each host
  fix_errata_on hosts

  # Detect cases in which no examples are executed (e.g., nodeset does not
  # have hosts with required roles)
  c.fail_if_no_examples = true

  # Readable test descriptions
  c.formatter = :documentation

  # Configure all nodes in nodeset
  c.before :suite do
    # Ensure the audit package is present before any tests run. On some EL10
    # Vagrant images (minimal install) it is not included by default, which
    # causes Facter's simplib__auditd fact to be absent and prevents Puppet
    # from finding auditctl on the first catalog apply.
    hosts.each do |host|
      # Reinstall audit so that auditctl is guaranteed to be present. On some
      # minimal libvirt images the package metadata shows audit as installed
      # but the binary is absent; a plain `dnf install` is a no-op in that
      # case, while `dnf reinstall` restores any missing files. If audit is
      # not installed at all the reinstall fails and the plain install runs.
      on(host, 'dnf reinstall -y audit 2>/dev/null || dnf install -y audit || yum install -y audit')
      on(host, 'echo "auditctl: $(which auditctl 2>/dev/null || echo NOT_FOUND)"',
         accept_all_exit_codes: true)
    end

    # Install modules and dependencies from spec/fixtures/modules
    copy_fixture_modules_to(hosts)
    begin
      server = only_host_with_role(hosts, 'server')
    rescue ArgumentError => e
      server = only_host_with_role(hosts, 'default')
    end

    # Generate and install PKI certificates on each SUT
    Dir.mktmpdir do |cert_dir|
      run_fake_pki_ca_on(server, hosts, cert_dir)
      hosts.each { |sut| copy_pki_to(sut, cert_dir, '/etc/pki/simp-testing') }
    end

    # add PKI keys
    copy_keydist_to(server)
  rescue StandardError, ScriptError => e
    raise e unless ENV['PRY']
    require 'pry'
    binding.pry # rubocop:disable Lint/Debugger
  end
end
