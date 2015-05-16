# == Class: auditd::grub
#
# Enables/disables auditing at boot time.
#
# == Parameters
#
# [*ensure*]
#    Whether to set to '0' or '1'
#
# == Authors
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class auditd::grub (
  $ensure = 'present'
) {

  if $ensure == 'present' {
    $l_ensure = '1'
  }
  else {
    $l_ensure = '0'
  }

  reboot_notify { 'audit': subscribe => Kernel_parameter['audit'] }

  kernel_parameter { 'audit': value => $l_ensure }

  validate_array_member($ensure, ['present','absent'])
}
