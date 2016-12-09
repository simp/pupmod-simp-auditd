# == Class: auditd::config::grub
#
# Enables/disables auditing at boot time.
#
# == Parameters
#
# [*enable*]
# Type: Boolean
# Default: true
#   Enable auditing in the kernel at boot time.
#
class auditd::config::grub (
  Boolean $enable = true
) {

  if $enable {
    $_enable = '1'
  }
  else {
    $_enable = '0'
  }

  kernel_parameter { 'audit': value => $_enable }

  reboot_notify { 'audit': subscribe => Kernel_parameter['audit'] }
}
