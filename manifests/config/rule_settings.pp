# @summary Last-one-wins audit settings, in a file that sorts after the
#   audit package's own rules
#
# augenrules concatenates `rules.d/*.rules` in `ls -1v` order and keeps only
# the last `-b` and `-f` it reads; `-r`, `--backlog_wait_time` and
# `--loginuid-immutable` take effect in order, so the last one wins too. The
# audit package's `rules.d/audit.rules` sets `-b 8192`, `-f 1` and
# `--backlog_wait_time 60000`, and every file whose name starts with a digit
# sorts before it. Putting these settings in a file named after it lets an
# explicitly set value take effect without purging anything, and leaves the
# package's or an admin's value in force for anything unset.
#
# @api private
#
class auditd::config::rule_settings {
  assert_private()

  # Must sort after "audit.rules" under `ls -1v`.
  $_path = '/etc/audit/rules.d/puppet_auditd.rules'

  # The heavier root audit levels need a larger backlog than 'basic' for the
  # profile rules they generate. They raise an unset or smaller buffer_size
  # to a floor; 'absent' still wins.
  $_buffer_floor = empty($auditd::config::profiles) ? {
    true    => undef,
    default => { 'aggressive' => 32788, 'insane' => 65576 }[$auditd::root_audit_level],
  }

  $_buffer_size = ($_buffer_floor =~ Integer and $auditd::buffer_size !~ Enum['absent']) ? {
    true    => max(pick($auditd::buffer_size, 0), $_buffer_floor),
    default => $auditd::buffer_size,
  }

  $_settings = {
    'buffer_size'        => { 'value' => $_buffer_size,               'line' => "-b ${_buffer_size}",                                 'match' => '^-b\s' },
    'failure_mode'       => { 'value' => $auditd::failure_mode,       'line' => "-f ${auditd::failure_mode}",                         'match' => '^-f\s' },
    'rate'               => { 'value' => $auditd::rate,               'line' => "-r ${auditd::rate}",                                 'match' => '^-r\s' },
    'backlog_wait_time'  => { 'value' => $auditd::backlog_wait_time,  'line' => "--backlog_wait_time ${auditd::backlog_wait_time}", 'match' => '^--backlog_wait_time\s' },
    'loginuid_immutable' => { 'value' => $auditd::loginuid_immutable, 'line' => '--loginuid-immutable',                               'match' => '^--loginuid-immutable\s*$' },
  }.filter |$_name, $d| { $d['value'] =~ NotUndef }

  # purge_auditd_rules deletes the package's rules.d/audit.rules, the only
  # other source of -b. With no -b anywhere the kernel keeps its default
  # backlog of 64. Put the package's value back, but only while this file
  # has no -b of its own.
  $_restore_packaged_b = $auditd::purge_auditd_rules and $_buffer_size =~ Undef

  if !empty($_settings) or $_restore_packaged_b {
    file { $_path:
      ensure  => 'file',
      require => Package[$auditd::package_name],
      *       => $auditd::config::rule_file_attributes,
    }
  }

  $_settings.each |$name, $d| {
    $_line = $d['value'] ? { false => undef, 'absent' => undef, default => $d['line'] }

    auditd::config::rule_line { "rule settings ${name}":
      path    => $_path,
      match   => $d['match'],
      line    => $_line,
      require => File[$_path],
    }
  }

  if $_restore_packaged_b {
    file_line { 'rule settings packaged -b':
      path    => $_path,
      line    => '-b 8192',
      match   => '^-b\s',
      replace => false,
      require => File[$_path],
    }
  }
}
