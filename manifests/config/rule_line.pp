# @summary Manage one directive in a rules.d file this module edits in place
#
# @api private
#
# @param path
#   The rules file.
#
# @param match
#   An anchored regex matching every form of the directive, so a changed value
#   replaces the old line instead of adding a second one.
#
# @param line
#   The directive to write. `undef` removes every line matching `$match`.
#
define auditd::config::rule_line (
  Stdlib::Absolutepath $path,
  String[1]            $match,
  Optional[String[1]]  $line = undef,
) {
  assert_private()

  if $line =~ Undef {
    file_line { $title:
      ensure            => 'absent',
      path              => $path,
      match             => $match,
      match_for_absence => true,
      multiple          => true,
    }
  }
  else {
    file_line { $title:
      path     => $path,
      line     => $line,
      match    => $match,
      multiple => true,
    }
  }
}
