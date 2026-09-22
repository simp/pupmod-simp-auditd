# NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# @summary Provides global audit rule configuration and a base set of audit rules based on the built-in audit profile(s).
#
# The configuration generated is contained in a set of files in
# `/etc/audit/rules.d`, which `augenrules` parses for `auditd` in
# natural sort order, to create a single `/etc/audit/auditd.rules`
# file. The generated files are as follows:
# - `00_head.rules`:  Contains `auditctl` general configuration to
#   remove existing rules when the rules are reloaded, ignore rule
#   load errors/failures, and set the buffer size, failure mode,
#   and rate limiting
# - `05_default_drop.rules`: Contains filtering rules for efficiency
#   - Rules to drop prolific events of low-utility
#   - Rules to restrict events based on `auid` constraints that would
#     normally be applied to all rules
# - `50_*base.rules`:
#   - Nominal base rules for one or more built-in profiles.
#   - One file will exist for each desired, built-in profile
#   - Files are named so that the ordering of profiles listed
#     in `$auditd::default_audit_profiles` is preserved
#   - The corresponding class for each profile is
#    `auditd::config::audit_profiles::<profile name>`
# - `60_custom.rules`: Custom rules as defined by the ``auditd::custom_rules``
#   parameter if appending
# - `75.init.d_auditd.rules`:
#    - A watch rule for `/etc/rc.d/init.d/auditd` permissions changes
#    - A watch rule for permissions changes to the `auditd` log file
# - `75.rotated_audit_logs.rules`
#    - Watch rules for permissions changes to the rotated `auditd` log files
# - `99_tail.rules`
#   - `auditctl` immutable option, when `$auditd::immutable` is 'true'
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::audit_profiles {
  assert_private()

  $_common_template_path = "${module_name}/rule_profiles/common"

  if $auditd::audit_auditd_config {
    # log_file is unset unless a site moves the audit log. auditd's own
    # default is /var/log/audit/audit.log, so that is the directory to watch
    # when nobody has said otherwise.
    $_audit_log_dir = dirname(pick($auditd::log_file, '/var/log/audit/audit.log'))

    auditd::rule { 'audit_auditd_config':
      content => [
        '-w /etc/rc.d/init.d/auditd -p wa -k auditd',
        "-w ${$_audit_log_dir} -p wa -k audit-logs",
        '-w /etc/audit/ -p wa -k auditconfig',
        '-w /etc/libaudit.conf -p wa -k auditconfig',
        '-w /sbin/auditctl -p x -k audittools',
        '-w /usr/sbin/auditctl -p x -k audittools',
        '-w /sbin/auditd -p x -k audittools',
        '-w /usr/sbin/auditd -p x -k audittools'
      ]
    }
  }

  if ( $auditd::root_audit_level == 'aggressive' ) and ( $auditd::buffer_size < 32788 ) {
    $_buffer_size = 32788
  } elsif ( $auditd::root_audit_level == 'insane' ) and ( $auditd::buffer_size < 65576 ) {
    $_buffer_size = 65576
  } else {
    $_buffer_size = $auditd::buffer_size
  }

  file { '/etc/audit/rules.d/00_head.rules':
    *       => $auditd::config::rule_file_attributes,
    content => epp("${_common_template_path}/head.epp"),
    require => Package[$auditd::package_name],
  }

  # The audit package ships its own preamble as rules.d/audit.rules (-D, -b,
  # --backlog_wait_time, -f). augenrules lets the later-sorting file win on a
  # duplicated directive and audit.rules sorts after 00_head.rules, so leaving
  # it in place silently overrides the values written above. With
  # purge_auditd_rules this is already removed; this covers the case where it
  # is not.
  file { '/etc/audit/rules.d/audit.rules':
    ensure  => 'absent',
    require => Package[$auditd::package_name],
  }

  # The tail is preamble and belongs with the head. The default drop rules are
  # profile content, so they are only written when a profile was asked for. If
  # the only profile is the 'built_in' profile, skip both to allow users more
  # control/flexibility over what they want to use.
  unless ( length($auditd::config::profiles)  == 1 ) and ( 'built_in' in $auditd::config::profiles ) {
    unless empty($auditd::config::profiles) {
      file { '/etc/audit/rules.d/05_default_drop.rules':
        *       => $auditd::config::rule_file_attributes,
        content => epp("${_common_template_path}/default_drop.epp"),
        require => Package[$auditd::package_name],
      }
    }

    file { '/etc/audit/rules.d/99_tail.rules':
      *       => $auditd::config::rule_file_attributes,
      content => epp("${_common_template_path}/tail.epp"),
      require => Package[$auditd::package_name],
    }
  }

  $auditd::config::profiles.each | String $audit_profile | {
    # use contain instead of include so that config file changes can
    # notify auditd::service class
    contain "auditd::config::audit_profiles::${audit_profile}"
  }
}
