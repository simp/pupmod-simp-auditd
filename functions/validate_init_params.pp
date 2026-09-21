# @summary Validates selected params from the main auditd class.
#
# Moved into a function to reduce class clutter.
#
# Fails on discovered errors.
#
# @return [None]
#
function auditd::validate_init_params {
  $_space_left       = $auditd::space_left
  $_admin_space_left = $auditd::admin_space_left

  # Both parameters are unset unless a site asks for them. There is nothing to
  # validate about a value nobody set, and 'in' against undef fails the
  # catalog. A Pattern match covers both: it is false for undef and for an
  # Integer without a separate type test.
  #
  # Do not be tempted back into `($x =~ String) and ('%' in $x)`: `and` binds
  # looser than `=`, so that assigns only the String test and throws the
  # rest away.
  $_space_left_pct       = $_space_left =~ Pattern[/%/]
  $_admin_space_left_pct = $_admin_space_left =~ Pattern[/%/]

  if $_space_left_pct or $_admin_space_left_pct {
    if $facts['auditd_version'] and ( versioncmp($facts['auditd_version'], '2.8.5') < 0 ) {
      fail('$space_left and $admin_space_left cannot contain "%" in auditd < 2.8.5')
    }
  }

  # auditd refuses to start when space_left is not greater than
  # admin_space_left. space_left is no longer derived from admin_space_left, so
  # a site that sets only the latter would write its value and leave whatever
  # the package ships (75 at the time of writing) in place -- taking the
  # service down on the next restart. Refuse the catalog rather than guess a
  # threshold on the site's behalf.
  if $_admin_space_left =~ NotUndef and $_space_left =~ Undef {
    fail(@(MSG/L))
      $auditd::admin_space_left is set but $auditd::space_left is not. auditd \
      requires space_left to be greater than admin_space_left or it will not \
      start, and the value shipped by the package is not guaranteed to be. Set \
      $auditd::space_left explicitly; auditd::calculate_space_left() derives \
      the value previous releases used.
      | MSG
  }

  if $_space_left =~ NotUndef and $_admin_space_left =~ NotUndef {
    if $_space_left.type('generalized') == $_admin_space_left.type('generalized') {
      if $_admin_space_left =~ String {
        if Integer($_admin_space_left.regsubst(/%$/, '')) > Integer($_space_left.regsubst(/%$/, '')) {
          fail('Auditd requires $space_left to be greater than $admin_space_left, otherwise it will not start')
        }
      } else {
        if $_admin_space_left > $_space_left {
          fail('Auditd requires $space_left to be greater than $admin_space_left, otherwise it will not start')
        }
      }
    } else {
      debug('$auditd::space_left and $auditd::admin_space_left are not of the same data type, cannot compare for sanity')
    }
  }
}
