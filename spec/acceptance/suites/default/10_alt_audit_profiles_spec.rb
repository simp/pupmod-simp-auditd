require 'spec_helper_acceptance'

# Returns list of errors and a list or warnings
# This logic ASSUMES the augenrules error log has 2 lines for each
# error and 1 line for each warning, as follows:
# ...
#   Error sending add rule data request (No such file or directory)
#   There was an error in line 272 of /etc/audit/audit.rules
#   Error sending add rule data request (Rule exists)
#   There was an error in line 305 of /etc/audit/audit.rules
#   WARNING - 32/64 bit syscall mismatch in line 159, you should specify an arch
# ...
#
def get_rule_errors_and_warnings(host, ignore = [], print_findings = true)
  result = on(host, 'augenrules --load', :accept_all_exit_codes => true)

  # warnings
  rule_warnings = result.stderr.split("\n").delete_if { |line| !line.include?('WARNING') }

  # errors
  errors = result.stderr.split("\n").delete_if { |line| line.include?('WARNING') }
  rule_errors = []
  errors.each_slice(2) do |line_pair|
    match = line_pair[0].match(/.*\((.*)\)/)
    if match
      err_msg = match[1]
    else
      err_msg = line_pair[0].strip
    end
    line_num = line_pair[1].match(%r{error in line (.+) of /etc/audit/audit.rules})[1]
    rule = on(host, "sed -n #{line_num}p /etc/audit/audit.rules").stdout.strip
    rule_errors << [err_msg, line_num, rule]
  end
  rule_errors.sort { |x,y|  x[0] <=> y[0] }

  if print_findings
    unless rule_warnings.empty?
      puts '<'*10 + ' Rule warnings ' + '<'*10
      rule_warnings.each { |rule_warning | puts rule_warning }
    end

    unless rule_errors.empty?
      puts '<'*10 + ' Rule errors ' + '<'*10
      rule_errors.each do |rule_error |
        puts "#{rule_error[0]}: #{rule_error[2]}  (line #{rule_error[1]})"
      end
    end
  end

  # filter out rules that match ignore list
  rule_errors.delete_if { |rule_error| ignore.include?(rule_error[0]) }

  [rule_errors, rule_warnings]
end

test_name 'auditd class with alternative auditd profiles'

# The fundamental module capabilities are tested in 00_base_spec.rb and
# 99_disable_audit_kernel_spec.rb.  The purpose of the tests in this
# file this is to verify each profile generates valid audit rules.
#
describe 'auditd class with alternative audit profiles' do
  let(:hieradata) {
    {
      'simp_options::syslog'    => true,
      'pki::cacerts_sources'    => ['file:///etc/pki/simp-testing/pki/cacerts'] ,
      'pki::private_key_source' => "file:///etc/pki/simp-testing/pki/private/%{fqdn}.pem",
      'pki::public_key_source'  => "file:///etc/pki/simp-testing/pki/public/%{fqdn}.pub",
    }
  }

  let(:simp_profile_aggressive) {
    {
      'auditd::root_audit_level' => 'aggressive',
    }.merge(hieradata)
  }

  let(:simp_profile_insane_enable_optional) {
    {
      'auditd::root_audit_level'                                 => 'insane',
      'auditd::config::audit_profiles::simp::audit_chmod'        => true,
      'auditd::config::audit_profiles::simp::audit_rename_remove'=> true,
      'auditd::config::audit_profiles::simp::audit_umask'        => true,
      'auditd::config::audit_profiles::simp::audit_selinux_cmds' => true,
      'auditd::config::audit_profiles::simp::audit_yum_cmd'      => true,
      'auditd::config::audit_profiles::simp::audit_rpm_cmd'      => true,
    }.merge(hieradata)
  }

  let(:stig_profile) {
    {
      'auditd::default_audit_profiles' => [ 'stig' ]
    }.merge(hieradata)
  }

  let(:simp_plus_stig_profiles) {
    {
      'auditd::default_audit_profiles' => [ 'simp', 'stig' ]
    }.merge(hieradata)
  }

  let(:manifest) {
    <<-EOS
      class { 'auditd': }
    EOS
  }

  hosts.each do |host|
    context "on #{host}" do

      context 'with simp profile, aggressive su-root auditing ' do
        it 'should work with no errors' do
          set_hieradata_on(host, simp_profile_aggressive)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be running the auditd service' do
          result = on(host, 'puppet resource service auditd')
          expect(result.output).to include("ensure => 'running'")
        end

        it 'should be running the audit dispatcher' do
          on(host, 'pgrep audispd')
        end

        it 'should load valid rules' do
          # make sure the rules have been regenerated
          # (search for rule only contained in new rule set)
          retry_on(host, 'grep execve /etc/audit/audit.rules | grep renameat',
            { :max_retries => 30, :verbose => true })

          on(host, 'cat /etc/audit/audit.rules')
          result = on(host, "auditctl -l")
          expect(result.stdout).to_not match(/No rules/)

          # get errors and warnings from augenrules, ignoring watch rules
          # for any file for which its parent directory does not exist.
          ignore = ['No such file or directory']
          rule_errors, rule_warnings = get_rule_errors_and_warnings(host, ignore)
          expect(rule_errors.size).to eq 0

          # No rule warnings should be emitted
          expect(rule_warnings.size).to eq 0
        end
      end

      context 'with simp profile, insane su-root auditing, all optional auditing enabled' do
        it 'should work with no errors' do
          set_hieradata_on(host, simp_profile_insane_enable_optional)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be running the auditd service' do
          result = on(host, 'puppet resource service auditd')
          expect(result.output).to include("ensure => 'running'")
        end

        it 'should be running the audit dispatcher' do
          on(host, 'pgrep audispd')
        end

        it 'should load valid rules' do
          # make sure the rules have been regenerated
          # (search for tag only contained in new rule set)
          retry_on(host, 'grep package_changes /etc/audit/audit.rules',
            { :max_retries => 30, :verbose => true })

          on(host, 'cat /etc/audit/audit.rules')
          result = on(host, "auditctl -l")
          expect(result.stdout).to_not match(/No rules/)

          # get errors and warnings from augenrules, ignoring watch rules
          # for any file for which its parent directory does not exist.
          ignore = ['No such file or directory']
          rule_errors, rule_warnings = get_rule_errors_and_warnings(host, ignore)
          expect(rule_errors.size).to eq 0

          # No rule warnings should be emitted
          rule_warnings = result.stderr.split("\n").delete_if { |line| !line.include?('WARNING') }
          expect(rule_warnings.size).to eq 0
        end
      end

      context 'with stig audit profile with default parameters' do
        it 'should work with no errors' do
          set_hieradata_on(host, stig_profile)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be running the auditd service' do
          result = on(host, 'puppet resource service auditd')
          expect(result.output).to include("ensure => 'running'")
        end

        it 'should be running the audit dispatcher' do
          on(host, 'pgrep audispd')
        end

        it 'should load valid rules' do
          # make sure the rules have been regenerated
          # (search for tag only contained in new rule set)
          retry_on(host, 'cat /etc/audit/audit.rules | grep identity',
            { :max_retries => 30, :verbose => true })

          on(host, 'cat /etc/audit/audit.rules')
          result = on(host, "auditctl -l")
          expect(result.stdout).to_not match(/No rules/)

          # get errors and warnings from augenrules, ignoring watch rules
          # for any file for which its parent directory does not exist.
          ignore = ['No such file or directory']
          rule_errors, rule_warnings = get_rule_errors_and_warnings(host, ignore)
          expect(rule_errors.size).to eq 0

          # No rule warnings should be emitted
          expect(rule_warnings.size).to eq 0
        end
      end

      context 'with simp + stig audit profiles, both with default parameters' do
        it 'should work with no errors' do
          set_hieradata_on(host, simp_plus_stig_profiles)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should load valid rules' do
          # make sure the rules have been regenerated
          # (search for tag only contained in new rule set)
          retry_on(host, 'cat /etc/audit/audit.rules | grep su-root-activity',
            { :max_retries => 30, :verbose => true })

          on(host, 'cat /etc/audit/audit.rules')
          result = on(host, "auditctl -l")
          expect(result.stdout).to_not match(/No rules/)

          # get errors and warnings from augenrules, ignoring duplicate rules
          # and watch rules for any file for which its parent directory does
          # not exist.
          ignore = ['Rule exists', 'No such file or directory']
          rule_errors, rule_warnings = get_rule_errors_and_warnings(host, ignore)
          expect(rule_errors.size).to eq 0

          # No rule warnings should be emitted
          expect(rule_warnings.size).to eq 0
        end
      end
    end
  end
end
