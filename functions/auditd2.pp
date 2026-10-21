# @summary Whether the host runs auditd 2 (EL7, unsupported since 9.0.0)
#
# A missing `auditd_version` fact counts as 3.0. The fact needs `auditctl`,
# which on EL10 comes from the `audit-rules` package this module installs in
# the same run, and every supported release ships audit 3 or later.
#
# The auditd 2 layout goes away in 12.0.0, along with this function.
#
# @return [Boolean]
#
function auditd::auditd2() >> Boolean {
  versioncmp(pick($facts['auditd_version'], '3.0'), '3.0') < 0
}
