# @summary A set of audit rules that are configured to satisfy DISA STIG compliance checks for EL7.
#
# The defaults for this profile generate a set of audit rules that conform to
# automated DISA STIG compliance checks for RHEL7. Satisfying the checks,
# instead of the intent of the security requirements, necessitates unoptimized
# rules. These unoptimized rules, in turn, negatively impact system performance.
#
# WARNING: **These rules may overload your system and/or log server!**
#
# When auditd performance is an issue, you may wish to
#
# * Disable capabilities that, despite being required by DISA STIG for RHEL7,
#   produce large amounts audit records of limited utility. `chmod` auditing
#   for all non-service users falls in this category.
#
# * Use the optimized 'auditd::config::audit_profiles::simp' profile, instead.
#   That profile is more comprehensive and performant.
#
#
# @param uid_min
#   The minimum UID for human users on the system. Any audit events generated
#   by users below this number will be ignored unless a corresponding rule
#   is inserted *before* the UID-limiting rule in the rules list.  When using
#   `auditd::rule`, you can create such a rule by setting the `absolute`
#   parameter to be 'first'.
#
# @param audit_unsuccessful_file_operations
#   Whether to audit unsuccessful file operations.  These are file operations
#   that fail with EACCES or EPERM error codes
#
# @param audit_unsuccessful_file_operations_tag
#   The tag to identify the unsuccessful file operations in an audit record
#
# @param audit_chown
#   Whether to audit `chown` operations for all non-service users.
#   These operations are provided by `chown`, `fchown`, `fchownat`,
#   and `lchown` system calls.
#
# @param audit_chown_tag
#   The tag to identify `chown` operations in an audit record
#
# @param audit_chmod
#   Whether to audit `chmod` operations for all non-service users.
#   These operations are provided by `chmod`, `fchmod`, and `fchmodat`
#   system calls.
#
# @param audit_chmod_tag
#   The tag to identify `chmod` operations in an audit record
#
# @param audit_attr
#   Whether to audit `xattr` operations for all non-service users.
#   These operations are provided by `setxattr`, `lsetxattr`, `fsetxattr`,
#   `removexattr`, `lremovexattr` and `fremovexattr` system calls.
#
# @param audit_attr_tag
#   The tag to identify `xattr` operations in an audit record
#
# @param audit_rename_remove
#   Whether to audit rename/remove operations for all non-service users.
#   These operations are provided by `rename`, `renameat`, `rmdir`,
#   `unlink`, and `unlinkat` system calls.
#
# @param audit_rename_remove_tag
#   The tag to identify rename/remove operations in an audit record
#
# @param audit_suid_sgid
#   Whether to audit `setuid`/`setgid` commands
#
# @param default_suid_sgid_cmds
#   The default list of `setuid`/`setgid` commands to be audited.
#   * Should not include commands audited by other rules.
#
# @param suid_sgid_cmds
#   Additional list of `setuid`/`setgid` commands to be audited.
#   You can use this to augment the `$default_suid_sgid_cmds`
#   per your site's needs.
#
#   As a Hash, an entry set to `ensure => absent` removes that command's rule,
#   including one from `$default_suid_sgid_cmds`, while `audit_suid_sgid` is
#   `true`. Deleting an entry from either list leaves its rule alone.
#
# @param audit_suid_tag
#   The tag to identify `setuid` command execution in an audit record
#
# @param audit_sgid_tag
#   The tag to identify `setgid` command execution in an audit record
#
# @param audit_suid_sgid_tag
#   The tag to identify `setuid`/`setgid` command execution in an audit record
#
# @param audit_kernel_modules
#   Whether to audit kernel module operations
#
# @param audit_kernel_modules_tag
#   The tag to identify kernel module operations in an audit record
#
# @param audit_mount
#   Whether to audit mount operations
#
# @param audit_mount_tag
#   The tag to identify mount operations in an audit record
#
# @param audit_local_account
#   Whether to audit local account changes
#
# @param audit_local_account_tag
#   The tag to identify local account changes in an audit record
#
# @param audit_selinux_cmds
#   Whether to audit `chcon`, `semanage`, `setsebool`, and `setfiles` commands
#
# @param audit_selinux_cmds_tag
#   The tag to identify selinux command execution in an audit record
#
# @param audit_login_files
#   Whether to audit changes to login files
#
# @param audit_login_files_tag
#   The tag to identify login file changes in an audit record
#
# @param audit_cfg_sudoers
#   Whether to audit changes to sudoers configuration files
#
# @param audit_cfg_sudoers_tag
#   The tag to identify sudoers configuration file changes in an audit record
#
# @param audit_passwd_cmds
#   Whether to audit the execution of password commands, i.e., `passwd`,
#   `unix_chkpwd`, `gpasswd`, `chage`, `userhelper`
#
# @param audit_passwd_cmds_tag
#   The tag to identify password command execution in an audit record
#
# @param audit_priv_cmds
#   Whether to audit the execution of privilege-related commands, i.e.,
#   `su`, `sudo`, `newgrp`, `chsh`, and `sudoedit`
#
# @param audit_priv_cmds_tag
#   The tag to identify privilege-related command execution in an audit record
#
# @param audit_postfix_cmds
#   Whether to audit the execution of postfix-related commands, i.e.
#   `postdrop` and `postqueue`
#
# @param audit_postfix_cmds_tag
#   The tag to identify postfix-related command execution in an audit record
#
# @param audit_ssh_keysign_cmd
#   Whether to audit the execution of the `ssh-keysign` command
#
# @param audit_ssh_keysign_cmd_tag
#   The tag to identify `ssh-keysign` command execution in an audit record
#
# @param audit_crontab_cmd
#   Whether to audit the execution of the `crontab` command
#
# @param audit_crontab_cmd_tag
#   The tag to identify `crontab` command execution in an audit record
#
# @param audit_pam_timestamp_check_cmd
#   Whether to audit the execution of the `pam_timestamp_check` command
#
# @param audit_pam_timestamp_check_cmd_tag
#   The tag to identify `pam_timestamp_check` command execution in an audit
#   record
#
class auditd::config::audit_profiles::stig (
  Integer[0]        $uid_min                                = $auditd::uid_min,
  Optional[Boolean] $audit_unsuccessful_file_operations     = undef,
  String[1]         $audit_unsuccessful_file_operations_tag = 'access',
  Optional[Boolean] $audit_chown                            = undef,
  String[1]         $audit_chown_tag                        = 'perm_mod',
  Optional[Boolean] $audit_chmod                            = undef,
  String[1]         $audit_chmod_tag                        = 'perm_mod',
  Optional[Boolean] $audit_attr                             = undef,
  String[1]         $audit_attr_tag                         = 'perm_mod',
  Optional[Boolean] $audit_rename_remove                    = undef,
  String[1]         $audit_rename_remove_tag                = 'delete',
  Optional[Boolean] $audit_suid_sgid                        = undef,
  Auditd::EntryList $default_suid_sgid_cmds,                   #data in modules
  Auditd::EntryList $suid_sgid_cmds                         = [],
  String[1]         $audit_suid_tag                         = 'setuid',
  String[1]         $audit_sgid_tag                         = 'setgid',
  String[1]         $audit_suid_sgid_tag                    = "${audit_suid_tag}/${audit_sgid_tag}",
  Optional[Boolean] $audit_kernel_modules                   = undef,
  String[1]         $audit_kernel_modules_tag               = 'module-change',
  Optional[Boolean] $audit_mount                            = undef,
  String[1]         $audit_mount_tag                        = 'privileged-mount',
  Optional[Boolean] $audit_local_account                    = undef,
  String[1]         $audit_local_account_tag                = 'identity',
  Optional[Boolean] $audit_selinux_cmds                     = undef,
  String[1]         $audit_selinux_cmds_tag                 = 'privileged-priv_change',
  Optional[Boolean] $audit_login_files                      = undef,
  String[1]         $audit_login_files_tag                  = 'logins',
  Optional[Boolean] $audit_cfg_sudoers                      = undef,
  String[1]         $audit_cfg_sudoers_tag                  = 'privileged-actions',
  Optional[Boolean] $audit_passwd_cmds                      = undef,
  String[1]         $audit_passwd_cmds_tag                  = 'privileged-passwd',
  Optional[Boolean] $audit_priv_cmds                        = undef,
  String[1]         $audit_priv_cmds_tag                    = 'privileged-priv_change',
  Optional[Boolean] $audit_postfix_cmds                     = undef,
  String[1]         $audit_postfix_cmds_tag                 = 'privileged-postfix',
  Optional[Boolean] $audit_ssh_keysign_cmd                  = undef,
  String[1]         $audit_ssh_keysign_cmd_tag              = 'privileged-ssh',
  Optional[Boolean] $audit_crontab_cmd                      = undef,
  String[1]         $audit_crontab_cmd_tag                  = 'privileged-cron',
  Optional[Boolean] $audit_pam_timestamp_check_cmd          = undef,
  String[1]         $audit_pam_timestamp_check_cmd_tag      = 'privileged-pam',
) {
  assert_private()
  # An entry in suid_sgid_cmds overrides the same entry in the defaults.
  $_suid_sgid_cmds = auditd::list_entries($default_suid_sgid_cmds) + auditd::list_entries($suid_sgid_cmds)

  $_short_name = 'stig'
  $_idx = auditd::get_array_index($_short_name, $auditd::config::profiles)
  $_path = "/etc/audit/rules.d/50_${_idx}_${_short_name}_base.rules"

  # Matched on any auid>= value, so a changed uid_min replaces these rules.
  $_auid = "-F auid>=${uid_min} -F auid!=unset"

  # In the order the rules were written before 11.0.0. The kernel records the
  # key of the first rule an event matches, so for rules that overlap, order
  # decides which tag an event gets.
  $_all_toggles = [
    ['audit_unsuccessful_file_operations', $audit_unsuccessful_file_operations, $audit_unsuccessful_file_operations_tag, [
      "-a always,exit -F arch=b64 -S creat -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b64 -S creat -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b32 -S creat -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b32 -S creat -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b64 -S open -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b64 -S open -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b32 -S open -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b32 -S open -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b64 -S openat -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b64 -S openat -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b32 -S openat -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b32 -S openat -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b64 -S truncate -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b64 -S truncate -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b32 -S truncate -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b32 -S truncate -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES ${_auid}",
      "-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM ${_auid}",
      "-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES ${_auid}",
    ]],
    ['audit_passwd_cmds', $audit_passwd_cmds, $audit_passwd_cmds_tag, [
      "-a always,exit -F path=/usr/bin/passwd -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/passwd -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x ${_auid}",
      "-a always,exit -F path=/sbin/unix_chkpwd -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/bin/gpasswd -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/gpasswd -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/bin/chage -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/chage -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/sbin/userhelper -F perm=x ${_auid}",
      "-a always,exit -F path=/sbin/userhelper -F perm=x ${_auid}",
    ]],
    ['audit_priv_cmds', $audit_priv_cmds, $audit_priv_cmds_tag, [
      "-a always,exit -F path=/usr/bin/su -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/su -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/bin/sudo -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/sudo -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/bin/newgrp -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/newgrp -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/bin/chsh -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/chsh -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/bin/sudoedit -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/sudoedit -F perm=x ${_auid}",
    ]],
    ['audit_postfix_cmds', $audit_postfix_cmds, $audit_postfix_cmds_tag, [
      "-a always,exit -F path=/usr/sbin/postdrop -F perm=x ${_auid}",
      "-a always,exit -F path=/sbin/postdrop -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/sbin/postqueue -F perm=x ${_auid}",
      "-a always,exit -F path=/sbin/postqueue -F perm=x ${_auid}",
    ]],
    ['audit_ssh_keysign_cmd', $audit_ssh_keysign_cmd, $audit_ssh_keysign_cmd_tag, [
      "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x ${_auid}",
    ]],
    ['audit_crontab_cmd', $audit_crontab_cmd, $audit_crontab_cmd_tag, [
      "-a always,exit -F path=/usr/bin/crontab -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/crontab -F perm=x ${_auid}",
    ]],
    ['audit_pam_timestamp_check_cmd', $audit_pam_timestamp_check_cmd, $audit_pam_timestamp_check_cmd_tag, [
      "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x ${_auid}",
      "-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x ${_auid}",
    ]],
    ['audit_selinux_cmds', $audit_selinux_cmds, $audit_selinux_cmds_tag, [
      "-a always,exit -F path=/usr/sbin/semanage -F perm=x ${_auid}",
      "-a always,exit -F path=/sbin/semanage -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/sbin/setsebool -F perm=x ${_auid}",
      "-a always,exit -F path=/sbin/setsebool -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/bin/chcon -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/chcon -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/sbin/setfiles -F perm=x ${_auid}",
      "-a always,exit -F path=/sbin/setfiles -F perm=x ${_auid}",
      "-a always,exit -F path=/sbin/restorecon -F perm=x ${_auid}",
      "-a always,exit -F path=/usr/sbin/restorecon -F perm=x ${_auid}",
    ]],
    ['audit_chown', $audit_chown, $audit_chown_tag, [
      "-a always,exit -F arch=b64 -S chown ${_auid}",
      "-a always,exit -F arch=b32 -S chown ${_auid}",
      "-a always,exit -F arch=b64 -S fchown ${_auid}",
      "-a always,exit -F arch=b32 -S fchown ${_auid}",
      "-a always,exit -F arch=b64 -S lchown ${_auid}",
      "-a always,exit -F arch=b32 -S lchown ${_auid}",
      "-a always,exit -F arch=b64 -S fchownat ${_auid}",
      "-a always,exit -F arch=b32 -S fchownat ${_auid}",
    ]],
    ['audit_chmod', $audit_chmod, $audit_chmod_tag, [
      "-a always,exit -F arch=b64 -S chmod ${_auid}",
      "-a always,exit -F arch=b32 -S chmod ${_auid}",
      "-a always,exit -F arch=b64 -S fchmod ${_auid}",
      "-a always,exit -F arch=b32 -S fchmod ${_auid}",
      "-a always,exit -F arch=b64 -S fchmodat ${_auid}",
      "-a always,exit -F arch=b32 -S fchmodat ${_auid}",
    ]],
    ['audit_attr', $audit_attr, $audit_attr_tag, [
      "-a always,exit -F arch=b64 -S setxattr ${_auid}",
      "-a always,exit -F arch=b32 -S setxattr ${_auid}",
      "-a always,exit -F arch=b64 -S fsetxattr ${_auid}",
      "-a always,exit -F arch=b32 -S fsetxattr ${_auid}",
      "-a always,exit -F arch=b64 -S lsetxattr ${_auid}",
      "-a always,exit -F arch=b32 -S lsetxattr ${_auid}",
      "-a always,exit -F arch=b64 -S removexattr ${_auid}",
      "-a always,exit -F arch=b32 -S removexattr ${_auid}",
      "-a always,exit -F arch=b64 -S fremovexattr ${_auid}",
      "-a always,exit -F arch=b32 -S fremovexattr ${_auid}",
      "-a always,exit -F arch=b64 -S lremovexattr ${_auid}",
      "-a always,exit -F arch=b32 -S lremovexattr ${_auid}",
    ]],
    ['audit_rename_remove', $audit_rename_remove, $audit_rename_remove_tag, [
      "-a always,exit -F arch=b64 -S rename ${_auid}",
      "-a always,exit -F arch=b32 -S rename ${_auid}",
      "-a always,exit -F arch=b64 -S renameat ${_auid}",
      "-a always,exit -F arch=b32 -S renameat ${_auid}",
      "-a always,exit -F arch=b64 -S rmdir ${_auid}",
      "-a always,exit -F arch=b32 -S rmdir ${_auid}",
      "-a always,exit -F arch=b64 -S unlink ${_auid}",
      "-a always,exit -F arch=b32 -S unlink ${_auid}",
      "-a always,exit -F arch=b64 -S unlinkat ${_auid}",
      "-a always,exit -F arch=b32 -S unlinkat ${_auid}",
    ]],
    ['audit_suid_sgid', $audit_suid_sgid, $audit_suid_sgid_tag, [
      ['-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0', $audit_suid_tag],
      ['-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0', $audit_sgid_tag],
      ['-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0', $audit_suid_tag],
      ['-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0', $audit_sgid_tag],
    ], { 'key_option' => '-k' }],
    ['audit_suid_sgid_cmds', $audit_suid_sgid, $audit_suid_sgid_tag,
      $_suid_sgid_cmds.map |$cmd, $ensure| { { 'rule' => "-a always,exit -F path=${cmd} -F perm=x ${_auid}", 'ensure' => $ensure } },
    ],
    ['audit_kernel_modules', $audit_kernel_modules, $audit_kernel_modules_tag, [
      '-w /usr/bin/kmod -p x -F auid!=unset',
      '-w /bin/kmod -p x -F auid!=unset',
      '-w /usr/sbin/insmod -p x -F auid!=unset',
      '-w /sbin/insmod -p x -F auid!=unset',
      '-w /usr/sbin/rmmod -p x -F auid!=unset',
      '-w /sbin/rmmod -p x -F auid!=unset',
      '-w /usr/sbin/modprobe -p x -F auid!=unset',
      '-w /sbin/modprobe -p x -F auid!=unset',
      '-a always,exit -F arch=b64 -S create_module',
      '-a always,exit -F arch=b32 -S create_module',
      '-a always,exit -F arch=b64 -S init_module',
      '-a always,exit -F arch=b32 -S init_module',
      '-a always,exit -F arch=b64 -S finit_module',
      '-a always,exit -F arch=b32 -S finit_module',
      '-a always,exit -F arch=b64 -S delete_module',
      '-a always,exit -F arch=b32 -S delete_module',
    ]],
    ['audit_mount', $audit_mount, $audit_mount_tag, [
      "-a always,exit -F arch=b64 -S mount ${_auid}",
      "-a always,exit -F arch=b64 -F path=/usr/bin/mount ${_auid}",
      "-a always,exit -F arch=b64 -F path=/bin/mount ${_auid}",
      "-a always,exit -F arch=b32 -S mount ${_auid}",
      "-a always,exit -F arch=b32 -F path=/usr/bin/mount ${_auid}",
      "-a always,exit -F arch=b32 -F path=/bin/mount ${_auid}",
      "-a always,exit -F path=/usr/bin/umount -F perm=x ${_auid}",
      "-a always,exit -F path=/bin/umount -F perm=x ${_auid}",
    ]],
    ['audit_local_account', $audit_local_account, $audit_local_account_tag, [
      '-w /etc/passwd -p wa',
      '-w /etc/group -p wa',
      '-w /etc/gshadow -p wa',
      '-w /etc/shadow -p wa',
      '-w /etc/security/opasswd -p wa',
    ]],
    ['audit_login_files', $audit_login_files, $audit_login_files_tag, [
      '-w /var/log/tallylog -p wa',
      '-w /var/run/faillock -p wa',
      '-w /var/log/lastlog -p wa',
    ]],
    ['audit_cfg_sudoers', $audit_cfg_sudoers, $audit_cfg_sudoers_tag, [
      '-w /etc/sudoers -p wa',
      '-w /etc/sudoers.d/ -p wa',
    ]],
  ]

  # Rules more than one toggle writes, whether or not those toggles are set, so
  # that a rule's match does not change when another toggle is turned on.
  $_shared_rules = $_all_toggles.map |$t| {
    $t[3].map |$entry| { $entry ? { String => $entry, Hash => $entry['rule'], default => $entry[0] } }
  }.flatten.group_by |$rule| { $rule }.filter |$rule, $copies| { $copies.length > 1 }.keys

  $_toggles = $_all_toggles.filter |$t| { $t[1] =~ Boolean }

  # Declared while the purge is on even with no toggle set: undeclared, the
  # purge would delete the rules an unset toggle is meant to leave alone.
  if $auditd::purge_auditd_rules or !empty($_toggles) {
    file { $_path:
      ensure  => 'file',
      require => Package[$auditd::package_name],
      *       => $auditd::config::rule_file_attributes,
    }

    $_toggles.each |$t| {
      auditd::config::profile_rules { "${_short_name} ${t[0]}":
        path         => $_path,
        enable       => $t[1],
        key          => $t[2],
        rules        => $t[3],
        shared_rules => $_shared_rules,
        require      => File[$_path],
        *            => { 'key_option' => '-F key=' } + pick($t[4], {}),
      }
    }
  }
}
