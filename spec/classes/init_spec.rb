require 'spec_helper'

describe 'auditd' do
  shared_examples_for 'a structured module' do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to create_class('auditd') }
    it { is_expected.to contain_class('auditd') }
    it { is_expected.to contain_class('auditd::install').that_comes_before('Class[auditd::config]') }
    it { is_expected.to contain_class('auditd::config') }
    it { is_expected.to contain_class('auditd::service').that_subscribes_to('Class[auditd::config]') }
  end

  # The blast-radius contract, stated as a test.
  #
  # Naming the absent resources individually is what makes a failure readable,
  # but a named list can only catch what it was written to catch. The equality
  # check below is the tripwire: any resource this module starts managing by
  # default, for any reason, fails here and has to be argued for on purpose.
  shared_examples_for 'a package-only catalogue' do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_package('audit') }

    it { is_expected.not_to contain_service('auditd') }
    it { is_expected.not_to contain_kernel_parameter('audit') }
    it { is_expected.not_to contain_kernel_parameter('audit:all') }
    it { is_expected.not_to contain_reboot_notify('auditd service') }
    it { is_expected.not_to contain_file('/etc/audit') }
    it { is_expected.not_to contain_file('/etc/audit/rules.d') }
    it { is_expected.not_to contain_file('/etc/audit/auditd.conf') }
    it { is_expected.not_to contain_file('/etc/audit/audit.rules') }
    it { is_expected.not_to contain_file('/var/log/audit') }
    it { is_expected.not_to contain_class('auditd::config::grub') }
    it { is_expected.not_to contain_class('auditd::config::logging') }
    it { is_expected.not_to contain_class('auditd::config::audit_profiles') }

    it 'writes no auditd.conf settings' do
      settings = catalogue.resources.select { |r| r.type == 'Ini_setting' }.map(&:title)
      expect(settings).to be_empty
    end

    it 'manages nothing but the package' do
      managed = catalogue.resources
                         .reject { |r| ['Class', 'Stage', 'Node'].include?(r.type) }
                         .map(&:to_s)
                         .sort
      expect(managed).to eq(['Package[audit]'])
    end
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:base_facts) do
          os_facts.merge(
            {
              # Oldest version shipping with EL7
              auditd_version: '2.4.1',
              simplib__auditd: {
                'enabled' => true,
                'kernel_enforcing' => true,
              },
            },
          )
        end

        let(:facts) do
          base_facts
        end

        context 'auditd with default parameters' do
          let(:params) { {} }

          it_behaves_like 'a structured module'
          it_behaves_like 'a package-only catalogue'

          # grub_version is present in these facts, so the absence of the grub
          # class above is the module declining to act, not a missing fact.
          it { expect(facts[:grub_version]).not_to be_nil }
        end

        # The bare-metal case: none of the module's own facts have resolved yet,
        # which is what a first run against a host without the package looks
        # like. It must still compile, and still manage only the package.
        context 'with none of the auditd facts present' do
          let(:facts) do
            os_facts.reject do |k, _v|
              [:auditd_version, :auditd_major_version, :simplib__auditd, :grub_version, :auditd_auditctl_cmd].include?(k)
            end
          end
          let(:params) { {} }

          it_behaves_like 'a package-only catalogue'
        end

        # With no parameters passed, $package_ensure and $syslog resolve through
        # simplib::lookup('simp_options::package_ensure' / 'simp_options::syslog').
        # The hieradata fixture sets both to values distinct from the class
        # defaults ('installed' / false), so a pass proves the lookup path
        # (not the default) supplied them.
        # See spec/fixtures/hieradata/simp_options.yaml.
        context 'with simp_options site keys set in hiera' do
          let(:params) { {} }
          let(:hieradata) { 'simp_options' }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_package('audit').with(ensure: 'latest') }
          it { is_expected.to contain_class('auditd').with_syslog(true) }
          it { is_expected.to contain_class('auditd::config::logging') }
        end

        # An explicit parameter wins over the simp_options fallback. The values
        # are deliberately distinct from the class defaults ('installed' /
        # false) so a pass proves the parameter carried them.
        context 'with package_ensure and syslog set explicitly' do
          let(:params) do
            {
              package_ensure: 'latest',
              syslog: true,
            }
          end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_package('audit').with(ensure: 'latest') }
          it { is_expected.to contain_class('auditd').with_syslog(true) }
          it { is_expected.to contain_class('auditd::config::logging') }
        end

        context 'with the service managed' do
          let(:params) do
            {
              service_ensure: 'running',
              service_enable: true,
            }
          end

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to contain_service('auditd').with(
              ensure: 'running',
              enable: true,
              stop: '/usr/sbin/auditctl --signal stop',
              restart: '/usr/sbin/auditctl --signal stop; /usr/bin/systemctl start auditd',
            )
          }
        end

        # Either half of the service may be left alone. Managing 'enable'
        # without 'ensure' must not start or stop a running auditd.
        context 'with only service_enable set' do
          let(:params) { { service_enable: true } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_service('auditd').with_enable(true).with_ensure(nil) }
        end

        context 'with at_boot => true' do
          let(:params) { { at_boot: true } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('auditd::install').that_comes_before('Class[auditd::config::grub]') }
          it { is_expected.to contain_class('auditd::config::grub').with_enable(true) }

          # EL10 moved auditctl, augenrules and rules.d into audit-rules, which
          # audit does not require. The default covers the newest release; the
          # module data narrows it to audit alone on EL8 and EL9.
          it { is_expected.to contain_package('audit') }
          if os.split('-')[1].to_i >= 10
            it { is_expected.to contain_package('audit-rules') }
          else
            it { is_expected.not_to contain_package('audit-rules') }
          end

          context 'on a host without grub' do
            let(:facts) { super().merge(grub_version: nil) }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to contain_class('auditd::install') }
            it { is_expected.not_to contain_class('auditd::config::grub') }
          end
        end

        # First run on a host where auditctl isn't installed yet (EL10 before
        # audit-rules): the syslog plugin is configured in the same run
        # instead of one run later.
        context 'with syslog enabled and no auditd facts yet' do
          let(:facts) { base_facts.reject { |k, _v| [:auditd_version, :auditd_major_version, :simplib__auditd].include?(k) } }
          let(:params) { { syslog: true } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('auditd::config::audisp::syslog') }
          it { is_expected.not_to contain_class('auditd::config::audisp') }
        end

        context 'with at_boot => false' do
          let(:params) { { at_boot: false } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('auditd::config::grub').with_enable(false) }
        end

        # manifests/service.pp branches on $warn_if_reboot_required: when true it
        # emits a reboot_notify (warning that auditd cannot be (re)started until
        # the kernel is enforcing auditing) INSTEAD of managing the service
        # resource. Every other context exercises only the false branch, so this
        # pins the true branch -- otherwise the reboot path has no unit coverage.
        context 'with warn_if_reboot_required => true' do
          let(:params) { { warn_if_reboot_required: true } }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_reboot_notify('auditd service') }
          it { is_expected.not_to contain_service('auditd') }
        end

        context 'auditd with space_left < admin_space_left' do
          let(:params) do
            {
              space_left: 20,
              admin_space_left: 25,
            }
          end

          it { is_expected.to compile.and_raise_error(%r{Auditd requires \$space_left to be greater than \$admin_space_left, otherwise it will not start}) }
        end

        context 'with space_left as a percentage' do
          let(:params) do
            {
              space_left: '20%',
            }
          end

          it { is_expected.to compile.and_raise_error(%r{cannot contain "%"}) }
        end

        context 'with admin_space_left as a percentage' do
          let(:params) do
            {
              admin_space_left: '20%',
            }
          end

          it { is_expected.to compile.and_raise_error(%r{cannot contain "%"}) }
        end

        context 'auditd 2.8.5' do
          let(:facts) do
            base_facts.merge(auditd_version: '2.8.5')
          end

          context 'with space_left as a percentage' do
            let(:params) do
              {
                space_left: '20%',
              }
            end

            it { is_expected.to compile.with_all_deps }
          end

          # auditd will not start unless space_left is the greater of the two,
          # and the value the package ships is not guaranteed to be, so setting
          # admin_space_left alone derives space_left rather than leaving the
          # packaged value in place.
          context 'with admin_space_left as a percentage and no space_left' do
            let(:params) { { admin_space_left: '20%' } }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to contain_ini_setting('auditd.conf space_left').with_value('21%') }
          end

          context 'with admin_space_left as an Integer and no space_left' do
            let(:params) { { admin_space_left: 50 } }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to contain_ini_setting('auditd.conf space_left').with_value(80) }
          end

          # The other direction is fine: space_left alone is a complete
          # instruction, because the package's admin_space_left is below it.
          context 'with space_left as an Integer and no admin_space_left' do
            let(:params) { { space_left: 80 } }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to contain_ini_setting('auditd.conf space_left').with_value(80) }
            it { is_expected.not_to contain_ini_setting('auditd.conf admin_space_left') }
          end

          # The documented migration for a site that wants the value previous
          # releases computed: call the helper and pass the result in. The
          # literals here are what auditd::calculate_space_left returns for
          # these inputs, asserted directly in its own spec.
          context 'with both set, as the docs instruct' do
            let(:params) do
              {
                admin_space_left: 50,
                space_left: 80,
              }
            end

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to contain_class('auditd').with_space_left(80) }
            it { is_expected.to contain_ini_setting('auditd.conf space_left').with_value(80) }
            it { is_expected.to contain_ini_setting('auditd.conf admin_space_left').with_value(50) }
          end

          context 'with both set as percentages, as the docs instruct' do
            let(:params) do
              {
                admin_space_left: '20%',
                space_left: '21%',
              }
            end

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to contain_ini_setting('auditd.conf space_left').with_value('21%') }
            it { is_expected.to contain_ini_setting('auditd.conf admin_space_left').with_value('20%') }
          end

          context 'auditd with space_left < admin_space_left as percentages' do
            let(:params) do
              {
                space_left: '5%',
                admin_space_left: '25%',
              }
            end

            it { is_expected.to compile.and_raise_error(%r{Auditd requires \$space_left to be greater than \$admin_space_left, otherwise it will not start}) }
          end

          context 'auditd with space_left > admin_space_left as percentages' do
            let(:params) do
              {
                space_left: '25%',
                admin_space_left: '5%',
              }
            end

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to contain_class('auditd').with_space_left('25%').with_admin_space_left('5%') }
          end
        end

        # D6: 'enable' is deprecated, not removed.
        #
        # It used to mean three things at once -- run the service, audit at
        # boot, write the rules. Those are separate parameters now, so the old
        # switch only fills in the ones a site has not set for itself.
        context 'with the deprecated enable => true' do
          let(:params) { { enable: true } }

          # true was the old default and meant "do the normal thing". The normal
          # thing is now opt-in, so true asks for nothing beyond the package.
          it_behaves_like 'a package-only catalogue'
        end

        context 'with the deprecated enable => false' do
          let(:params) { { enable: false } }

          it { is_expected.to compile.with_all_deps }

          # install and config still run: 'enable => false' turns auditing off,
          # it does not un-manage the host. This differs from the old behaviour,
          # where the whole module stood down and the package went unmanaged.
          it { is_expected.to contain_class('auditd::install') }
          it { is_expected.to contain_class('auditd::config') }
          it { is_expected.to contain_package('audit') }

          it { is_expected.to contain_service('auditd').with_ensure('stopped').with_enable(false) }
          it { is_expected.to contain_class('auditd::config::grub').with_enable(false) }
        end

        # The shim never overrides a parameter that was set on purpose.
        context 'with enable => false and the service set explicitly' do
          let(:params) do
            {
              enable: false,
              service_ensure: 'running',
              service_enable: true,
              at_boot: true,
            }
          end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_service('auditd').with_ensure('running').with_enable(true) }
          it { is_expected.to contain_class('auditd::config::grub').with_enable(true) }
        end
      end
    end
  end

  context 'unsupported operating system' do
    describe 'auditd without any parameters on Solaris/Nexenta' do
      let(:facts) do
        {
          os: {
            'name' => 'Solaris',
          },
        }
      end

      it { expect { is_expected.to contain_package('auditd') }.to raise_error(Puppet::Error) }
    end
  end
end
