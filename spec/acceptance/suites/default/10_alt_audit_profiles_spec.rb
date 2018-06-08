require 'spec_helper_acceptance'

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

          result = on(host, 'augenrules --load', :accept_all_exit_codes => true)
          rule_errors = result.stderr.split("\n").delete_if { |line| !line.include?('error in line') }
          rule_errors.map! { |line| line=line.match(%r{error in line (.+) of /etc/audit/audit.rules})[1] }
          rule_errors.uniq!

          # Again, only the watch rule for /etc/snmp/snmpd.conf should
          # be rejected because the watche file's parent directory does
          # not exist
          expect(rule_errors.size).to eq 1
          result = on(host, "sed -n #{rule_errors[0]}p /etc/audit/audit.rules")
          expect(result.stdout).to match(%r{/etc/snmp/snmpd.conf})

          # No rule warnings should be emitted
          rule_warnings = result.stderr.split("\n").delete_if { |line| !line.include?('WARNING') }
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

          result = on(host, 'augenrules --load', :accept_all_exit_codes => true)
          rule_errors = result.stderr.split("\n").delete_if { |line| !line.include?('error in line') }
          rule_errors.map! { |line| line=line.match(%r{error in line (.+) of /etc/audit/audit.rules})[1] }
          rule_errors.uniq!

          # Again, only the watch rule for /etc/snmp/snmpd.conf should
          # be rejected because the watche file's parent directory does
          # not exist
          expect(rule_errors.size).to eq 1
          result = on(host, "sed -n #{rule_errors[0]}p /etc/audit/audit.rules")
          expect(result.stdout).to match(%r{/etc/snmp/snmpd.conf})

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

          result = on(host, 'augenrules --load', :accept_all_exit_codes => true)
          rule_errors = result.stderr.split("\n").delete_if { |line| !line.include?('error in line') }
          rule_errors.map! { |line| line=line.match(%r{error in line (.+) of /etc/audit/audit.rules})[1] }
          rule_errors.uniq!

          if host.host_hash['platform'] =~ /el-6/
            # We expect no rules to be rejected
            expected = []
          else
            # We expect 5 file watch rules to be rejected because the
            # packages for those files have not been installed, and thus
            # the paths to those files do not exist.
            expected = [
              '/usr/lib64/dbus-1/dbus-daemon-launch-helper',
              '/usr/libexec/sssd/krb5_child',
              '/usr/libexec/sssd/ldap_child',
              '/usr/libexec/sssd/proxy_child',
              '/usr/libexec/sssd/selinux_child'
            ]
          end

          errors = []
          rule_errors.each do |index|
            rule = on(host, "sed -n #{index}p /etc/audit/audit.rules").stdout
            errors << rule.match(/.* path=(.*?) .*/)[1]
          end
          expect(errors.size).to eq expected.size
          expect(expected - errors).to be_empty

          # No rule warnings should be emitted
          rule_warnings = result.stderr.split("\n").delete_if { |line| !line.include?('WARNING') }
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

          result = on(host, 'augenrules --load', :accept_all_exit_codes => true)
          rule_errors = result.stderr.split("\n").delete_if { |line| !line.include?('error in line') }
          rule_errors.map! { |line| line=line.match(%r{error in line (.+) of /etc/audit/audit.rules})[1] }
          rule_errors.uniq!

          if host.host_hash['platform'] =~ /el-6/
            # We expect 1 watch rule from simp profile to be rejected,
            # because its parent directory does not exist.
            # In addition, we expect 3 duplicate rules to be rejected.
            expected = [
              '/etc/snmp/snmpd.conf',
              '/var/log/lastlog',
              '/var/log/tallylog',
              '/var/run/faillock'
            ]
          else
            # We expect 6 file watch rules to be rejected, because
            # their parent directories do not exist:
            # - 1 from simp profile
            # - 5 from stig profile
            #
            # We expect 1 watch rule from simp profile to be rejected.
            expected = [
              '/etc/snmp/snmpd.conf',
              '/usr/lib64/dbus-1/dbus-daemon-launch-helper',
              '/usr/libexec/sssd/krb5_child',
              '/usr/libexec/sssd/ldap_child',
              '/usr/libexec/sssd/proxy_child',
              '/usr/libexec/sssd/selinux_child',
              '/var/log/lastlog',
              '/var/log/tallylog',
              '/var/run/faillock'
            ]
          end

          errors = []
          rule_errors.each do |index|
            rule = on(host, "sed -n #{index}p /etc/audit/audit.rules").stdout
            match = rule.match(/ path=(.*?) -|^-w (.*) -p/)
            errors << (match[1] or match[2])
          end
          expect(errors.size).to eq expected.size
          expect(expected - errors).to be_empty

          # No rule warnings should be emitted
          rule_warnings = result.stderr.split("\n").delete_if { |line| !line.include?('WARNING') }
          expect(rule_warnings.size).to eq 0
        end
      end
    end
  end
end
