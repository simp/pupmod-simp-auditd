require 'spec_helper_acceptance'

test_name 'warn_if_reboot_required on a kernel that is enforcing auditing'

# warn_if_reboot_required replaces managing the service with a reboot_notify
# only while the kernel is not enforcing auditing. On a kernel that is, a rule
# change must still reach the running rule set without a reboot: here through
# the managed service's restart, with only `service_enable` set, which is how
# compliance data typically asks for the service.
#
# This runs while the kernel is auditing; 99_disable_audit_kernel_spec.rb
# covers the kernel that is not.
describe 'auditd with warn_if_reboot_required' do
  let(:manifest) { "class { 'auditd': }" }

  let(:base_hieradata) do
    {
      'auditd::default_audit_profiles'                    => ['custom'],
      'auditd::config::audit_profiles::custom::rules'     => ['-w /etc/hosts -p wa -k warn_if_reboot_required'],
      'auditd::log_group'                                 => 'root',
      'auditd::config_group'                              => 'root',
    }
  end

  hosts.each do |host|
    context "on #{host}" do
      it 'starts from a running auditd on an auditing kernel' do
        set_hieradata_on(host, base_hieradata.merge(
          'auditd::service_ensure' => 'running',
          'auditd::service_enable' => true,
        ))
        apply_manifest_on(host, manifest, catch_failures: true)

        expect(pfact_on(host, 'auditd_state')['kernel_enforcing']).to be true
      end

      context 'with a rule added while warn_if_reboot_required is set' do
        let(:hieradata) do
          base_hieradata.merge(
            'auditd::warn_if_reboot_required'               => true,
            'auditd::service_enable'                        => true,
            'auditd::config::audit_profiles::custom::rules' => [
              '-w /etc/hosts -p wa -k warn_if_reboot_required',
              '-w /etc/hostname -p wa -k warn_if_reboot_required_added',
            ],
          )
        end

        it 'applies with no errors' do
          set_hieradata_on(host, hieradata)
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, catch_changes: true)
        end

        it 'loads the new rule without a reboot' do
          expect(on(host, 'auditctl -l').stdout).to include('-w /etc/hostname -p wa -k warn_if_reboot_required_added')
        end

        it 'leaves auditd running' do
          on(host, 'systemctl is-active auditd')
        end
      end
    end
  end
end
