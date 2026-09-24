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

  $_head = '/etc/audit/rules.d/00_head.rules'
  $_drop = '/etc/audit/rules.d/05_default_drop.rules'
  $_tail = '/etc/audit/rules.d/99_tail.rules'

  # These three files are edited line by line, never rendered whole. Each
  # directive follows its parameter: undef leaves whatever is in the file,
  # false or 'absent' removes the line, anything else writes it. A partial
  # compliance profile therefore changes only what it sets, and never reverts
  # what an earlier profile or another tool applied.

  # The simp and stig profiles watch paths that may not exist on every host
  # (e.g. /etc/snmp). Without -c the kernel stops at the first rejected rule
  # and silently drops every rule after it, so either profile writes -c unless
  # ignore_failures says otherwise.
  $_ignore_failures = $auditd::ignore_failures ? {
    undef   => ('simp' in $auditd::config::profiles or 'stig' in $auditd::config::profiles) ? { true => true, default => undef },
    default => $auditd::ignore_failures,
  }

  # The heavier root audit levels need a larger backlog than 'basic'. They
  # raise an unset or smaller buffer_size to a floor; 'absent' still wins.
  $_buffer_floor = { 'aggressive' => 32788, 'insane' => 65576 }[$auditd::root_audit_level]

  $_buffer_size = ($_buffer_floor =~ Integer and $auditd::buffer_size !~ Enum['absent']) ? {
    true    => max(pick($auditd::buffer_size, 0), $_buffer_floor),
    default => $auditd::buffer_size,
  }

  # Created once. The seed carries the -b 8192 from the audit package's own
  # rules.d/audit.rules, which purge_auditd_rules deletes; after that the file
  # is only ever edited in place.
  file { $_head:
    ensure  => 'file',
    replace => false,
    content => "# Partially managed by Puppet (module 'auditd'). Lines for unset\n# parameters are left alone.\n-D\n-b 8192\n",
    require => Package[$auditd::package_name],
    *       => $auditd::config::rule_file_attributes,
  }

  # -D is not a setting: without it a reload stacks the module's rules on top
  # of the loaded set.
  auditd::config::rule_line { '00_head -D':
    path    => $_head,
    match   => '^-D\s*$',
    line    => '-D',
    require => File[$_head],
  }

  $_head_directives = {
    'ignore_errors'      => { 'value' => $auditd::ignore_errors,      'line' => '-i',                                                 'match' => '^-i\s*$' },
    'ignore_failures'    => { 'value' => $_ignore_failures,           'line' => '-c',                                                 'match' => '^-c\s*$' },
    'buffer_size'        => { 'value' => $_buffer_size,               'line' => "-b ${_buffer_size}",                                 'match' => '^-b\s' },
    'backlog_wait_time'  => { 'value' => $auditd::backlog_wait_time,  'line' => "--backlog_wait_time ${auditd::backlog_wait_time}", 'match' => '^--backlog_wait_time\s' },
    'failure_mode'       => { 'value' => $auditd::failure_mode,       'line' => "-f ${auditd::failure_mode}",                         'match' => '^-f\s' },
    'rate'               => { 'value' => $auditd::rate,               'line' => "-r ${auditd::rate}",                                 'match' => '^-r\s' },
    'loginuid_immutable' => { 'value' => $auditd::loginuid_immutable, 'line' => '--loginuid-immutable',                               'match' => '^--loginuid-immutable\s*$' },
  }

  $_head_directives.each |$name, $d| {
    unless $d['value'] =~ Undef {
      $_line = $d['value'] ? { false => undef, 'absent' => undef, default => $d['line'] }

      auditd::config::rule_line { "00_head ${name}":
        path    => $_head,
        match   => $d['match'],
        line    => $_line,
        require => File[$_head],
      }
    }
  }

  # The tail is preamble and belongs with the head. The default drop rules are
  # profile content, so they are only written when a profile was asked for. If
  # the only profile is the 'built_in' profile, skip both to allow users more
  # control/flexibility over what they want to use.
  unless ( length($auditd::config::profiles)  == 1 ) and ( 'built_in' in $auditd::config::profiles ) {
    unless empty($auditd::config::profiles) {
      file { $_drop:
        ensure  => 'file',
        require => Package[$auditd::package_name],
        *       => $auditd::config::rule_file_attributes,
      }

      $_chrony = '-S adjtimex -F auid=-1 -F uid=chrony -F subj_type=chronyd_t'

      $_drop_rules = {
        'anonymous'       => { 'value' => $auditd::ignore_anonymous,       'line' => '-a never,exit -F auid=-1' },
        'system_services' => { 'value' => $auditd::ignore_system_services, 'line' => "-a never,exit -F auid!=0 -F auid<${auditd::uid_min}", 'match' => '^-a never,exit -F auid!=0 -F auid<\d+$' },
        'crond'           => { 'value' => $auditd::ignore_crond,           'line' => '-a never,user -F subj_type=crond_t' },
        'chrony b32'      => { 'value' => $auditd::ignore_time_daemons,    'line' => "-a never,exit -F arch=b32 ${_chrony}" },
        'crypto_key_user' => { 'value' => $auditd::ignore_crypto_key_user, 'line' => '-a always,exclude -F msgtype=CRYPTO_KEY_USER' },
      } + ($facts['os']['hardware'] == 'x86_64' ? {
        true    => { 'chrony b64' => { 'value' => $auditd::ignore_time_daemons, 'line' => "-a never,exit -F arch=b64 ${_chrony}" } },
        default => {},
      })

      # target_selinux_types: an Array means "present" for each entry; a Hash
      # also takes ensure => absent, which is the only way to remove one.
      $_selinux_types = $auditd::target_selinux_types ? {
        Array   => $auditd::target_selinux_types.reduce({}) |$memo, $type| { $memo + { $type => {} } },
        default => pick($auditd::target_selinux_types, {}),
      }

      $_selinux_rules = $_selinux_types.reduce({}) |$memo, $entry| {
        $memo + {
          "selinux ${entry[0]}" => {
            'value' => $entry[1]['ensure'] != 'absent',
            'line'  => "-a never,user -F subj_type!=${entry[0]}",
          },
        }
      }

      ($_drop_rules + $_selinux_rules).each |$name, $d| {
        unless $d['value'] =~ Undef {
          $_line = $d['value'] ? { false => undef, default => $d['line'] }

          auditd::config::rule_line { "05_default_drop ${name}":
            path    => $_drop,
            # None of these lines contain regex metacharacters, so the line
            # anchored is its own match unless one is given.
            match   => pick($d['match'], "^${d['line']}$"),
            line    => $_line,
            require => File[$_drop],
          }
        }
      }
    }

    file { $_tail:
      ensure  => 'file',
      require => Package[$auditd::package_name],
      *       => $auditd::config::rule_file_attributes,
    }

    unless $auditd::immutable =~ Undef {
      $_immutable_line = $auditd::immutable ? { true => '-e 2', default => undef }

      auditd::config::rule_line { '99_tail immutable':
        path    => $_tail,
        match   => '^-e\s+2\s*$',
        line    => $_immutable_line,
        require => File[$_tail],
      }
    }
  }

  $auditd::config::profiles.each | String $audit_profile | {
    # use contain instead of include so that config file changes can
    # notify auditd::service class
    contain "auditd::config::audit_profiles::${audit_profile}"
  }
}
