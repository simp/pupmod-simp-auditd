# frozen_string_literal: true

# simp-rspec-puppet-facts returns only the factsets it ships, which cover EL
# alone, so `on_supported_os` silently skips the Ubuntu releases listed in
# metadata.json. This adds the FacterDB factsets for every supported release
# it skips.
#
# FacterDB factsets carry no custom facts, and their nested keys are Strings
# where the SIMP factsets use Symbols. The keys are symbolized to match, and
# the custom facts this module reads are added with the values an Ubuntu host
# reports with the packaged auditd installed.
SUPPORTED_OS_EXTRA_FACTS = {
  'ubuntu-22.04' => { auditd_version: '3.0.7', grub_version: '2.06' },
  'ubuntu-24.04' => { auditd_version: '3.1.2', grub_version: '2.12' },
}.freeze

# The sample rule sets the Ubuntu auditd package ships, by name and order.
UBUNTU_SAMPLE_RULESETS = {
  'base-config' => '10', 'no-audit' => '10', 'loginuid' => '11', 'cont-fail' => '12',
  'ignore-error' => '12', 'dont-audit' => '20', 'no32bit' => '21', 'ignore-chrony' => '22',
  'ignore-filesystems' => '23', 'nispom' => '30', 'ospp-v42' => '30', 'pci-dss-v31' => '30',
  'stig' => '30', 'privileged' => '31', 'power-abuse' => '32', 'local' => '40',
  'containers' => '41', 'injection' => '42', 'module-load' => '43', 'installers' => '44',
  'einval' => '70', 'networking' => '71', 'finalize' => '99'
}.transform_values { |order| { 'order' => order } }.freeze

def deep_symbolize_fact_keys(value)
  case value
  when Hash then value.to_h { |k, v| [k.to_sym, deep_symbolize_fact_keys(v)] }
  when Array then value.map { |v| deep_symbolize_fact_keys(v) }
  else value
  end
end

def supported_os_facts
  simp_facts = on_supported_os
  missing = RspecPuppetFacts.meta_supported_os.filter_map do |os|
    releases = os.fetch('operatingsystemrelease', []).reject do |rel|
      simp_facts.key?("#{os['operatingsystem'].downcase}-#{rel}-x86_64")
    end
    os.merge('operatingsystemrelease' => releases) unless releases.empty?
  end
  return simp_facts if missing.empty?

  extra = Simp::RspecPuppetFacts::Shim.on_supported_os(supported_os: missing).to_h do |os, facts|
    release_facts = SUPPORTED_OS_EXTRA_FACTS.fetch(os.split('-')[0..1].join('-'), {})
    auditd_version = release_facts[:auditd_version]

    facts = deep_symbolize_fact_keys(facts).merge(
      auditd_major_version: auditd_version&.split('.')&.first,
      simplib__auditd: {
        'enabled' => true,
        'enforcing' => true,
        'kernel_enforcing' => true,
        'version' => auditd_version,
      },
      uid_min: '1000',
      init_systems: ['rc', 'systemd'],
      auditd_sample_ruleset_location: '/usr/share/doc/auditd/examples/rules',
      auditd_sample_rulesets: UBUNTU_SAMPLE_RULESETS,
    ).merge(release_facts)

    [os, facts]
  end

  simp_facts.merge(extra)
end
