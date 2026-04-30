# @summary Enables/disables auditing at boot time.
#
# @param enable
#   Enable auditing in the kernel at boot time.
#
# @param augeasproviders_grub_version
#   The version of the puppet/augeasproviders_grub module in use. Versions
#   >= 6.0.0 use the kernel parameter name 'audit:all'; older versions use
#   'audit'. Defaults to the installed module version read from its metadata.
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::grub (
  Boolean $enable                       = true,
  String  $augeasproviders_grub_version = load_module_metadata('augeasproviders_grub')['version'],
) {
  if $enable {
    $_enable = '1'
  }
  else {
    $_enable = '0'
  }

  if versioncmp($augeasproviders_grub_version, '6.0.0') >= 0 {
    $_kernel_param = 'audit:all'
  }
  else {
    $_kernel_param = 'audit'
  }

  kernel_parameter { $_kernel_param: value => $_enable }

  reboot_notify { $_kernel_param: subscribe => Kernel_parameter[$_kernel_param] }
}
