require 'spec_helper_acceptance'

test_name 'auditd class'

describe 'auditd class' do
  let(:disable_hieradata) {
    {
      'auditd::at_boot' => false
    }
  }

  let(:manifest) {
    <<-EOS
      class { 'auditd': }
    EOS
  }

  hosts.each do |host|
    context 'default parameters' do
      # Using puppet_apply as a helper
      it 'should work with no errors' do
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

      it 'should send audit logs to syslog' do
        on(host, %(grep -qe 'audispd:.*msg=audit' /var/log/messages))
      end
    end

    context 'disabling auditd at the kernel level' do
      it 'should work with no errors' do
        set_hieradata_on(host, disable_hieradata)
        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      # Note: In SIMP, svckill will take care of actually disabling auditd if
      # it is no longer managed. Here, we're not including svckill by default.
      it 'should not kill the auditd service' do
        result = on(host, 'puppet resource service auditd')
        expect(result.output).to include("ensure => 'running'")
        expect(result.output).to include("enable => 'true'")
      end

      it 'should require reboot on subsequent run' do
        result = apply_manifest_on(host, manifest, :catch_failures => true)
        expect(result.output).to include('audit => modified')

        # Reboot to enable auditing in the kernel
        host.reboot
      end

      it 'should have kernel-level audit disabled on reboot' do
        on(host, 'grep "audit=0" /proc/cmdline')
      end
    end
  end
end
