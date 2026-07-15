require 'spec_helper_acceptance'

test_name 'auditd class with simp audit profile'

describe 'auditd class with simp audit profile' do
  require_relative('lib/util')

  let(:hieradata) do
    {
      'simp_options::syslog'                 => true,
      'pki::cacerts_sources'                 => ['file:///etc/pki/simp-testing/pki/cacerts'],
      'pki::private_key_source'              => 'file:///etc/pki/simp-testing/pki/private/%{facts.networking.fqdn}.pem',
      'pki::public_key_source'               => 'file:///etc/pki/simp-testing/pki/public/%{facts.networking.fqdn}.pub',
      'rsyslog::config::main_msg_queue_size' => 4321,
    }
  end

  let(:enable_audit_messages) do
    {
      'auditd::syslog'                                  => true,
      'auditd::config::audisp::syslog::enable'          => true,
      'auditd::config::audisp::syslog::drop_audit_logs' => false,
      'auditd::config::audisp::syslog::priority'        => 'LOG_NOTICE'
    }.merge(hieradata)
  end

  let(:disable_audit_messages) do
    {
      'auditd::config::audisp::syslog::enable'          => false,
      'auditd::config::audisp::syslog::syslog_priority' => 'LOG_NOTICE',
      'auditd::syslog'                                  => true
    }.merge(hieradata)
  end

  let(:manifest) do
    <<~EOS
      class { 'auditd': }
    EOS
  end

  hosts.each do |host|
    context "on #{host}" do
      # Exercise noop from a clean state: on a fresh node the Sicura console
      # previews the module with `puppet apply --noop`, which must not error.
      # This runs before the applies below configure auditd, so it is the
      # genuine fresh-node preview. A post-convergence noop check is omitted
      # (`--noop --detailed-exitcodes` always exits 0). No package removal (as
      # with fips/ssh): a fresh node already has the base `audit` package, so
      # the honest clean state is "installed but not yet SIMP-managed", which is
      # exactly what a bare noop of the module's manifest previews. Unlike the
      # real apply (`catch_failures: false`, since the auditd service cannot be
      # manually restarted), noop triggers no restart, so failures are real.
      context 'in noop mode from a clean state' do
        it 'applies without errors in noop mode' do
          apply_manifest_on(host, manifest, catch_failures: true, noop: true)
        end
      end

      context 'default parameters' do
        it 'works without errors' do
          set_hieradata_on(host, hieradata)
          # There is a guaranteed failure here because the auditd service cannot be restarted due to configuration
          # in the systemd: RefuseManualStop=yes.
          apply_manifest_on(host, manifest, catch_failures: false)
        end

        it 'requires reboot on subsequent run' do
          result = apply_manifest_on(host, manifest, catch_failures: true)
          expect(result.output).to include('audit:all => modified')
          # Reboot to enable auditing in the kernel
          host.reboot
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, catch_changes: true)
        end

        it 'has kernel-level audit enabled on reboot' do
          host.reboot
          on(host, 'grep "audit=1" /proc/cmdline')
        end

        it 'has the audit package installed' do
          result = YAML.safe_load(on(host, 'puppet resource package audit --to_yaml').stdout)
          expect(result['package']['audit']['ensure']).not_to eq('absent')
        end

        it 'activates the auditd service' do
          result = YAML.safe_load(on(host, 'puppet resource service auditd --to_yaml').stdout)
          expect(result['service']['auditd']['ensure']).to eq('running')
          expect(result['service']['auditd']['enable']).to eq('true')
        end

        it 'loads valid rules' do
          results = AuditdTestUtil::AuditdRules.new(host)

          expect(results.rules).not_to be_empty
          expect(results.warnings).to eq([])
          expect(results.errors).to eq([])
        end

        it 'does not send audit logs to syslog' do
          # log rotate so any audit messages present before the apply turned off
          # audit record logging are no longer in /var/log/secure
          on(host, 'logrotate --force /etc/logrotate.d/rsyslog; systemctl restart rsyslog; sleep 2')
          # cause an auditable event
          on(host, 'useradd thing1')
          on(host, %q(grep -qe 'acct="thing1".*exe="/usr/sbin/useradd"' /var/log/audit/audit.log))
          on(host, "grep -qe 'audispd.*msg=audit' /var/log/secure", acceptable_exit_codes: [1, 2])
        end

        it 'fixes incorrect permissions' do
          on(host, 'chmod 666 /var/log/audit/audit.log')
          # Ensure that puppet runs clean after rebooting to pick up audit changes
          apply_manifest_on(host, manifest, catch_failures: true)
          result = on(host, '/bin/find /var/log/audit/audit.log -perm 0600')
          expect(result.output).to include('/var/log/audit/audit.log')
        end
      end

      context 'allowing audit syslog messages' do
        let(:audit_major_version) do
          result = on(host, 'rpm -q --qf "%{VERSION}\n" audit')
          result.stdout.split('.')[0].to_i
        end

        # auditd 4.x uses a builtin syslog plugin; no separate dispatcher process
        let(:dispatcher) do
          if audit_major_version < 3
            'audispd'
          elsif audit_major_version < 4
            'audisp-syslog'
          end
        end

        it 'works with no errors' do
          set_hieradata_on(host, enable_audit_messages)
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'is running the audit dispatcher' do
          skip('auditd 4.x uses builtin syslog; no separate dispatcher process') unless dispatcher
          on(host, "pgrep #{dispatcher}")
        end

        it 'has audit.rules has been generated with SIMP rules' do
          # spot check that audit.rules has been generated with SIMP rules
          on(host, "{ #{AuditdTestUtil::AUDIT_RULES_CMD}; } | grep -qe '^-c$'")
          on(host, "{ #{AuditdTestUtil::AUDIT_RULES_CMD}; } | grep -qe '\\-a never,exit \\-F auid=-1'")
          on(host, "{ #{AuditdTestUtil::AUDIT_RULES_CMD}; } | grep -qe '\\-a always,exit \\-F perm=a \\-F exit=-EACCES \\-k access'")
          on(host, "{ #{AuditdTestUtil::AUDIT_RULES_CMD}; } | grep -qe '\\-w /var/log/audit -p wa \\-k audit-logs'")
          # spot check that loaded audit rules contain SIMP rules
          # NOTE:  Loaded rules are normalized as follows:
          #   - Implicit '-S all' is included in '-a' rules without a '-S' option
          #   - '-a' arguments are reordered to have action,list instead of list,action.
          #   - '-k keyname' arguments are expanded to '-F key=keyname' for '-a' rules
          result = on(host, "#{AuditdTestUtil::AUDITCTL_CMD} -l")
          expect(result.output).to include('-a never,exit -S all -F auid=-1')
          expect(result.output).to include('-a always,exit -S all -F perm=a -F exit=-EACCES -F key=access')
          # On El6 it adds / to the end of directories but not on later versions.
          expect(result.output).to match(%r{-w /var/log/audit[/]* \-p wa \-k audit\-logs})
        end

        it 'sends audit logs to syslog' do
          on(host, 'logrotate --force /etc/logrotate.d/rsyslog')

          # cause an auditable event and verify it is logged
          # log rotate so any audit messages present before the apply turned off
          # audit record logging are no longer in /var/log/secure
          on(host, 'useradd thing2')
          on(host, %q(grep -qe 'acct="thing2".*exe="/usr/sbin/useradd"' /var/log/audit/audit.log))

          if audit_major_version >= 4
            # auditd 4.x uses builtin syslog plugin; syslog identifier differs from 'audispd'.
            # Check syslog files first; fall back to journal (captures all syslog traffic on EL10).
            on(host, 'grep -rqe \'key="audit_account_changes"\' /var/log/secure /var/log/messages 2>/dev/null || ' \
                     'journalctl --since=-5min --no-pager -q 2>/dev/null | grep -q \'key="audit_account_changes"\'')
          else
            on(host, %q(grep -qe 'audispd.*type=SYSCALL msg=audit.*comm="useradd.*key="audit_account_changes"' /var/log/secure))
          end
        end

        it 'restarts the dispatcher if killed' do
          skip('auditd 4.x uses builtin syslog; no separate dispatcher process') unless dispatcher
          on(host, "pkill #{dispatcher}")
          apply_manifest_on(host, manifest, catch_failures: true)
          on(host, "pgrep #{dispatcher}")
        end
      end

      context 'disable audit syslog messages' do
        it 'works with no errors' do
          set_hieradata_on(host, disable_audit_messages)
          apply_manifest_on(host, manifest, catch_failures: true)
        end
        it 'is not logging messages to syslog' do
          # log rotate so any audit messages present before the apply turned off
          # audit record logging are no longer in /var/log/secure
          on(host, 'logrotate --force /etc/logrotate.d/rsyslog')
          on(host, 'useradd notathing')
        end
        describe file('/var/log/secure') do
          its(:content) { is_expected.not_to match %r{audispd.*acct="notathing"} }
        end
        describe file('/var/log/audit/audit.log') do
          its(:content) { is_expected.to match %r{acct="notathing".*exe="/usr/sbin/useradd"} }
        end
      end
    end
  end
end
