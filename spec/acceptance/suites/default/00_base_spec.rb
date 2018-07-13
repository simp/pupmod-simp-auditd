require 'spec_helper_acceptance'

test_name 'auditd class with simp audit profile'

describe 'auditd class with simp audit profile' do
  let(:hieradata) {
    {
      'simp_options::syslog'    => true,
      'pki::cacerts_sources'    => ['file:///etc/pki/simp-testing/pki/cacerts'] ,
      'pki::private_key_source' => "file:///etc/pki/simp-testing/pki/private/%{fqdn}.pem",
      'pki::public_key_source'  => "file:///etc/pki/simp-testing/pki/public/%{fqdn}.pub",
    }
  }

  let(:enable_audit_messages) {
    {
      'auditd::config::audisp::syslog::drop_audit_logs' => false,
      'auditd::config::audisp::syslog::syslog_priority' => 'LOG_NOTICE'
    }.merge(hieradata)
  }

  let(:manifest) {
    <<-EOS
      class { 'auditd': }
    EOS
  }

  hosts.each do |host|
    context "on #{host}" do
      context 'default parameters' do
        it 'should work with no errors' do
          set_hieradata_on(host, hieradata)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should require reboot on subsequent run' do
          result = apply_manifest_on(host, manifest, :catch_failures => true)
          expect(result.output).to include('audit => modified')
          # Reboot to enable auditing in the kernel
          host.reboot
        end

        it 'should have kernel-level audit enabled on reboot' do
          on(host, 'grep "audit=1" /proc/cmdline')
        end

        it 'should have the audit package installed' do
          result = on(host, 'puppet resource package audit')
          expect(result.output).to_not include("ensure => 'absent'")
        end

        it 'should activate the auditd service' do
          result = on(host, 'puppet resource service auditd')
          expect(result.output).to include("ensure => 'running'")
          expect(result.output).to include("enable => 'true'")
        end

        it 'should be running the audit dispatcher' do
          on(host, 'pgrep audispd')
        end

        it 'should load valid rules' do
          on(host, 'cat /etc/audit/audit.rules')
          result = on(host, 'auditctl -l')
          expect(result.stdout).to_not match(/No rules/)

          result = on(host, 'augenrules --load', :accept_all_exit_codes => true)
          rule_errors = result.stderr.split("\n").delete_if { |line| !line.include?('error in line') }
          rule_errors.map! { |line| line=line.match(%r{error in line (.+) of /etc/audit/audit.rules})[1] }
          rule_errors.uniq!

          # We expect one rule to be rejected: the watch for
          # /etc/snmp/snmpd.conf changes.  This rule should be rejected
          # because the watched file's parent directory does not exist.
          # (net-snmp package is not installed.)
          expect(rule_errors.size).to eq 1
          result = on(host, "sed -n #{rule_errors[0]}p /etc/audit/audit.rules")
          expect(result.stdout).to match(%r{/etc/snmp/snmpd.conf})

          # No rule warnings should be emitted
          rule_warnings = result.stderr.split("\n").delete_if { |line| !line.include?('WARNING') }
          expect(rule_warnings.size).to eq 0
        end

        it 'should restart the audit dispatcher if it is killed' do
          on(host, 'pkill audispd')
          apply_manifest_on(host, manifest, :catch_failures => true)
          on(host, 'pgrep audispd')
        end

        it 'should not send audit logs to syslog' do
          # log rotate so any audit messages present before the apply turned off
          # audit record logging are no longer in /var/log/secure
          on(host, 'logrotate --force /etc/logrotate.d/syslog')
          # cause an auditable event
          on(host,'useradd thing1')
          on(host, %(grep -qe 'audispd:.*msg=audit' /var/log/secure), :acceptable_exit_codes => [1,2])
        end

        it 'should fix incorrect permissions' do
          on(host, 'chmod 400 /var/log/audit/audit.log')
          apply_manifest_on(host, manifest, :catch_failures => true)
          result = on(host, "/bin/find /var/log/audit/audit.log -perm 0600")
          expect(result.output).to include('/var/log/audit/audit.log')
        end
      end

      context 'allowing audit syslog messages' do
        it 'should work with no errors' do
          set_hieradata_on(host, enable_audit_messages)
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should send audit logs to syslog' do
          # spot check that audit.rules has been generated with SIMP rules
          on(host, %(grep -qe '^-c$' /etc/audit/audit.rules))
          on(host, %q(grep -qe '\-a exit,never \-F auid=-1' /etc/audit/audit.rules))
          on(host, %q(grep -qe '\-a always,exit \-F perm=a \-F exit=-EACCES \-k access' /etc/audit/audit.rules))
          on(host, %q(grep -qe '\-w /var/log/audit/audit.log -p wa \-k audit-logs' /etc/audit/audit.rules))
          on(host, %q(grep -qe '\-w /var/log/audit/audit.log.5 \-p rwa \-k audit-logs' /etc/audit/audit.rules))

          # spot check that loaded audit rules contain SIMP rules
          # NOTE:  Loaded rules are normalized as follows:
          #   - Implicit '-S all' is included in '-a' rules without a '-S' option
          #   - '-a' arguments are reordered to have action,list instead of list,action.
          #   - '-k keyname' arguments are expanded to '-F key=keyname' for '-a' rules
          result = on(host, "auditctl -l")
          expect(result.output).to include('-a never,exit -S all -F auid=-1')
          expect(result.output).to include('-a always,exit -S all -F perm=a -F exit=-EACCES -F key=access')
          expect(result.output).to include('-w /var/log/audit/audit.log -p wa -k audit-logs')
          expect(result.output).to include('-w /var/log/audit/audit.log.5 -p rwa -k audit-logs')

          # cause an auditable event and verify it is logged
          on(host,'useradd thing2')
          on(host, %(grep -qe 'audispd:.*type=SYSCALL msg=audit.*comm="useradd.*key="audit_account_changes"' /var/log/secure))
        end
      end
    end
  end
end
