# @summary A set of general purpose audit rules that should meet most security policy requirements
#
# The defaults for this profile generate a set of audit rules that are
# both usable on most systems and conformant with standard auditing
# requirements. A few key usage/implementation details about this profile
# should be noted:
#
#   * This profile uses optimized audit rules.  Specifically, it
#     * Combines system call rules as much as possible
#     * By default, uses initial drop rules for the `auid` filters that
#       would be otherwise applied to all system call rules
#     * By default, uses an initial drop rule for cron events that are
#       prolific, but whose audit records are of very limited utility
#   * Although all security requirements allow optimization of audit rules,
#     most of the automated security scanners do not yet understand audit
#     rule optimizations. So, use of this profile may require explanation
#     of these simple, yet effective, optimizations.
#   * You may overload your system and/or log server, if you enable the
#     highly-prolific, but limited-utility audit capabilities that have been
#     intentionally disabled, here, despite being required by specific
#     security standards.  'chmod' auditing for all non-service users
#     is an example of such a capability.
#   * In some cases, the more targeted set of rules for non-service users
#     that have su'd to root may provide a viable subset of required auditing.
#     This targeting filtering is enabled by `$audit_su_root_activity` and
#     customized by `$root_audit_level`, `$basic_root_audit_syscalls`,
#     `$aggressive_root_audit_syscalls, and `$insane_root_audit_syscalls`.
#
# @param root_audit_level
#   What level of auditing should be used for su-root activity. Be aware that
#   setting this to anything besides 'basic' may overwhelm your system and/or
#   log server.
#   Options can be, 'basic', 'aggressive', 'insane'
#    - Basic: Safe syscall rules, should not follow program execution outside
#      of the base app
#    - Aggressive: Adds syscall rules for execve, rmdir and variants of rename
#      and unlink
#    - Insane: Adds syscall rules for write, creat and variants of chown,
#      fork, link and mkdir
#
# @param audit_32bit_operations
#   In general, any 32bit system calls on a 64bit systems should be seen as
#   suspicious.

#   Written only on x86_64; ignored elsewhere, even when `true`. Before 11.0.0
#   it defaulted to `false` off x86_64 but was written wherever it was `true`.
#
# @param audit_32bit_operations_tag
#   Tag to be added to entries triggered by `audit_32bit_operations`
#
# @param audit_auditd_cmds
#   Audit calls to the auditd management CLI commands
#
# @param audit_auditd_cmds_tag
#   Tag to be added to entries triggered by `audit_auditd_cmds`
#
# @param audit_auditd_cmds_list
#   Commands to be audited if enabled by `audit_auditd_cmds`
#
#   As a Hash, an entry set to `ensure => absent` removes its rule while the
#   toggle is `true`. Deleting an entry leaves its rule alone. A Hash in Hiera
#   replaces the module's default list rather than merging into it, so list
#   every entry to keep.
#
# @param basic_root_audit_syscalls
#   Basic syscalls to audit for su-root activity
#
#   As a Hash, an entry set to `ensure => absent` is left out of the rule's
#   `-S` list. A Hash in Hiera replaces the module's default list rather than
#   merging into it.
#
# @param aggressive_root_audit_syscalls
#   Aggressive syscalls to audit for su-root activity
#
#   As a Hash, an entry set to `ensure => absent` is left out of the rule's
#   `-S` list. A Hash in Hiera replaces the module's default list rather than
#   merging into it.
#
# @param insane_root_audit_syscalls
#   Insane syscalls to audit for su-root activity
#
#   As a Hash, an entry set to `ensure => absent` is left out of the rule's
#   `-S` list. A Hash in Hiera replaces the module's default list rather than
#   merging into it.
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
#   The tag to identify `chown` operations in an audit record.
#   You should change this to 'perm_mod' to match automated DISA STIG
#   compliance checks for RHEL7.
#
# @param audit_chmod
#   Whether to audit `chmod` operations for all non-service users.
#   These operations are provided by `chmod`, `fchmod`, and `fchmodat`
#   system calls.
#
# @param audit_chmod_tag
#   The tag to identify `chmod` operations in an audit record.
#   You should change this to 'perm_mod' to match automated DISA STIG
#   compliance checks for RHEL7.
#
# @param audit_attr
#   Whether to audit `xattr` operations for all non-service users.
#   These operations are provided by `setxattr`, `lsetxattr`, `fsetxattr`,
#   `removexattr`, `lremovexattr` and `fremovexattr` system calls.
#
# @param audit_attr_tag
#   The tag to identify `xattr` operations in an audit record.
#   You should change this to 'perm_mod' to match automated DISA STIG
#   compliance checks for RHEL7.
#
# @param audit_rename_remove
#   Whether to audit rename/remove operations for all non-service users.
#   These operations are provided by `rename`, `renameat`, `rmdir`,
#   `unlink`, and `unlinkat` system calls.
#
# @param audit_rename_remove_tag
#   The tag to identify rename/remove operations in an audit record
#
# @param audit_su_root_activity
#   Whether to audit other useful actions someone does when su'ing to root.
#   The list of system calls audited is controlled by `$root_audit_level`.
#
# @param audit_su_root_activity_tag
#   The tag to identify `su` operations in an audit record
#
# @param audit_suid_sgid
#   Whether to audit `setuid`/`setgid` commands.
#   `setuid`/`setgid` command execution is audited by a single system call
#   rule.
#
# @param audit_suid_sgid_tag
#   The tag to identify `setuid`/`setgid` command execution in an audit
#   record. You should change this to 'setuid/setgid' to match automated
#   DISA STIG compliance checks for RHEL7.
#
# @param audit_kernel_modules
#   Whether to audit kernel module operations
#
# @param audit_kernel_modules_tag
#   The tag to identify kernel module operations in an audit record.
#   You should change this to 'module-change' to match automated DISA STIG
#   compliance checks for RHEL7.
#
# @param audit_time
#   Whether to audit operations that affect system time
#
# @param audit_time_tag
#   The tag to identify system time operations in an audit record
#
# @param audit_locale
#   Whether to audit operations that affect system locale
#
# @param audit_locale_tag
#   The tag to identify system locale operations in an audit record
#
# @param audit_network_ipv4_accept
#   Audit **incoming** IPv4 connections
#
# @param audit_network_ipv4_accept_tag
#   Tag to be added to entries triggered by `audit_network_ipv4_accept`
#
# @param audit_network_ipv6_accept
#   Audit **incoming** IPv6 connections
#
# @param audit_network_ipv6_accept_tag
#   Tag to be added to entries triggered by `audit_network_ipv6_accept`
#
# @param audit_network_ipv4_connect
#   Audit **outgoing** IPv4 connections
#
# @param audit_network_ipv4_connect_tag
#   Tag to be added to entries triggered by `audit_network_ipv4_connect`
#
# @param audit_network_ipv6_connect
#   Audit **outgoing** IPv6 connections
#
# @param audit_network_ipv6_connect_tag
#   Tag to be added to entries triggered by `audit_network_ipv6_connect`
#
# @param audit_mount
#   Whether to audit mount operations
#
# @param audit_mount_tag
#   The tag to identify mount operations in an audit record.
#   You should change this to 'privileged-mount' to match automated DISA STIG
#   compliance checks for RHEL7.
#
# @param audit_umask
#   Whether to audit umask changes
#
# @param audit_umask_tag
#   The tag to identify umask changes in an audit record
#
# @param audit_local_account
#   Whether to audit local account changes
#
# @param audit_local_account_tag
#   The tag to identify local account changes in an audit record.
#   You should change this to 'identity' to match the automated DISA STIG
#   compliance checks for RHEL7.
#
# @param audit_selinux_policy
#   Whether to audit selinux policy changes
#
# @param audit_selinux_policy_tag
#   The tag to identify selinux policy changes in an audit record
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
# @param audit_session_files
#   Whether to audit changes to session files
#
# @param audit_session_files_tag
#   The tag to identify session file changes in an audit record
#
# @param audit_sudoers
#   Deprecated by `$audit_cfg_sudoers`
#
# @param audit_sudoers_tag
#   Deprecated by `$audit_cfg_sudoers_tag`
#
# @param audit_cfg_sudoers
#   Whether to audit changes to sudoers configuration files
#
# @param audit_cfg_sudoers_tag
#   The tag to identify sudoers configuration file changes in an audit
#   record.  You should change this to 'privileged-actions' to match the
#   automated DISA STIG compliance checks for RHEL7.
#
# @param audit_grub
#   Deprecated by `$audit_cfg_grub`
#
# @param audit_grub_tag
#   Deprecated by `$audit_cfg_grub_tag`
#
# @param audit_cfg_grub
#   Whether to audit changes to grub configuration files
#
# @param audit_cfg_grub_tag
#   The tag to identify grub configuration file changes in an audit record
#
# @param audit_cfg_sys
#   Whether to audit changes to key system configuration files not
#   otherwise audited
#
# @param audit_cfg_sys_tag
#   The tag to identify changes to key system configuration files
#   not otherwise audited
#
# @param audit_cfg_cron
#   Whether to audit changes to cron configuration files
#
# @param audit_cfg_cron_tag
#   The tag to identify cron configuration file changes in an audit
#   record
#
# @param audit_cfg_shell
#   Whether to audit changes to global shell configuration files
#
# @param audit_cfg_shell_tag
#   The tag to identify global shell configuration file changes in an
#   audit record
#
# @param audit_cfg_pam
#   Whether to audit changes to PAM configuration files
#
# @param audit_cfg_pam_tag
#   The tag to identify PAM configuration file changes in an audit record
#
# @param audit_cfg_security
#   Whether to audit changes to `/etc/security`
#
# @param audit_cfg_security_tag
#   The tag to identify `/etc/security` file changes in an audit record
#
# @param audit_cfg_services
#   Whether to audit changes to `/etc/services`
#
# @param audit_cfg_services_tag
#   The tag to identify `/etc/services` file changes in an audit record
#
# @param audit_cfg_xinetd
#   Whether to audit changes to xinetd configuration files
#
# @param audit_cfg_xinetd_tag
#   The tag to identify xinetd configuration file changes in an audit record
#
# @param audit_yum
#   Deprecated by `$audit_cfg_yum`
#
# @param audit_yum_tag
#   Deprecated by `$audit_cfg_yum_tag`
#
# @param audit_cfg_yum
#   Whether to audit changes to yum configuration files
#
# @param audit_cfg_yum_tag
#   The tag to identify yum configuration file changes in an audit record
#
# @param audit_yum_cmd
#   Whether to audit `yum` command execution
#
# @param audit_yum_cmd_tag
#   The tag to identify `yum` command execution in an audit record
#
# @param audit_rpm_cmd
#   Whether to audit `rpm` command execution
#
# @param audit_rpm_cmd_tag
#   The tag to identify `rpm` command execution in an audit record
#
# @param audit_ptrace
#   Whether to audit `ptrace` system calls
#
# @param audit_ptrace_tag
#   The tag to identify `ptrace` system calls in an audit record
#
# @param audit_personality
#   Whether to audit `personality` system calls
#
# @param audit_personality_tag
#   The tag to identify `personality` system calls in an audit record
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
# @param audit_suspicious_apps
#   Audit various applications that generally represent suspicious host activity
#
# @param audit_suspicious_apps_tag
#   Tag to be added to entries triggered by `audit_suspicious_apps`
#
# @param audit_suspicious_apps_list
#   List of applications to be audited when `audit_suspicious_apps` is enabled
#
#   As a Hash, an entry set to `ensure => absent` removes its rule while the
#   toggle is `true`. Deleting an entry leaves its rule alone. A Hash in Hiera
#   replaces the module's default list rather than merging into it, so list
#   every entry to keep.
#
# @param audit_systemd
#   Audit systemd components
#
#   * Only takes effect on systems with systemd present
#
# @param audit_systemd_tag
#   Tag to be added to entries triggered by `audit_systemd`
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
class auditd::config::audit_profiles::simp (
  Auditd::RootAuditLevel      $root_audit_level                                         = $auditd::root_audit_level,
  Optional[Boolean]           $audit_32bit_operations                                   = undef,
  String[1]                   $audit_32bit_operations_tag                               = '32bit-api',
  Optional[Boolean]           $audit_auditd_cmds                                        = undef,
  String[1]                   $audit_auditd_cmds_tag                                    = 'access-audit-trail',
  Auditd::EntryList           $audit_auditd_cmds_list,                                  # data in modules
  Optional[Boolean]           $audit_unsuccessful_file_operations                       = undef,
  String[1]                   $audit_unsuccessful_file_operations_tag                   = 'access',
  Optional[Boolean]           $audit_chown                                              = undef,
  String[1]                   $audit_chown_tag                                          = 'chown',
  Optional[Boolean]           $audit_chmod                                              = undef,
  String[1]                   $audit_chmod_tag                                          = 'chmod',
  Optional[Boolean]           $audit_attr                                               = undef,
  String[1]                   $audit_attr_tag                                           = 'attr',
  Optional[Boolean]           $audit_rename_remove                                      = undef,
  String[1]                   $audit_rename_remove_tag                                  = 'delete',
  Optional[Boolean]           $audit_su_root_activity                                   = undef,
  String[1]                   $audit_su_root_activity_tag                               = 'su-root-activity',
  Optional[Boolean]           $audit_suid_sgid                                          = undef,
  String[1]                   $audit_suid_sgid_tag                                      = 'suid-exec',
  Optional[Boolean]           $audit_kernel_modules                                     = undef,
  String[1]                   $audit_kernel_modules_tag                                 = 'modules',
  Optional[Boolean]           $audit_time                                               = undef,
  String[1]                   $audit_time_tag                                           = 'audit_time_rules',
  Optional[Boolean]           $audit_locale                                             = undef,
  String[1]                   $audit_locale_tag                                         = 'audit_network_modifications',
  Optional[Boolean]           $audit_network_ipv4_accept                                = undef,
  String[1]                   $audit_network_ipv4_accept_tag                            = 'ipv4_in',
  Optional[Boolean]           $audit_network_ipv6_accept                                = undef,
  String[1]                   $audit_network_ipv6_accept_tag                            = 'ipv6_in',
  Optional[Boolean]           $audit_network_ipv4_connect                               = undef,
  String[1]                   $audit_network_ipv4_connect_tag                           = 'ipv4_in',
  Optional[Boolean]           $audit_network_ipv6_connect                               = undef,
  String[1]                   $audit_network_ipv6_connect_tag                           = 'ipv6_in',
  Optional[Boolean]           $audit_mount                                              = undef,
  String[1]                   $audit_mount_tag                                          = 'mount',
  Optional[Boolean]           $audit_umask                                              = undef,
  String[1]                   $audit_umask_tag                                          = 'umask',
  Optional[Boolean]           $audit_local_account                                      = undef,
  String[1]                   $audit_local_account_tag                                  = 'audit_account_changes',
  Optional[Boolean]           $audit_selinux_policy                                     = undef,
  String[1]                   $audit_selinux_policy_tag                                 = 'MAC-policy',
  Optional[Boolean]           $audit_selinux_cmds                                       = undef,
  String[1]                   $audit_selinux_cmds_tag                                   = 'privileged-priv_change',
  Optional[Boolean]           $audit_login_files                                        = undef,
  String[1]                   $audit_login_files_tag                                    = 'logins',
  Optional[Boolean]           $audit_session_files                                      = undef,
  String[1]                   $audit_session_files_tag                                  = 'session',
  Optional[Boolean]           $audit_sudoers                                            = undef,
  Optional[String[1]]         $audit_sudoers_tag                                        = undef,
  Optional[Boolean]           $audit_cfg_sudoers                                        = undef,
  String[1]                   $audit_cfg_sudoers_tag                                    = 'CFG_sys',
  Optional[Boolean]           $audit_grub                                               = undef,
  Optional[String[1]]         $audit_grub_tag                                           = undef,
  Optional[Boolean]           $audit_cfg_grub                                           = undef,
  String[1]                   $audit_cfg_grub_tag                                       = 'CFG_grub',
  Optional[Boolean]           $audit_cfg_sys                                            = undef,
  String[1]                   $audit_cfg_sys_tag                                        = 'CFG_sys',
  Optional[Boolean]           $audit_cfg_cron                                           = undef,
  String[1]                   $audit_cfg_cron_tag                                       = 'CFG_cron',
  Optional[Boolean]           $audit_cfg_shell                                          = undef,
  String[1]                   $audit_cfg_shell_tag                                      = 'CFG_shell',
  Optional[Boolean]           $audit_cfg_pam                                            = undef,
  String[1]                   $audit_cfg_pam_tag                                        = 'CFG_pam',
  Optional[Boolean]           $audit_cfg_security                                       = undef,
  String[1]                   $audit_cfg_security_tag                                   = 'CFG_security',
  Optional[Boolean]           $audit_cfg_services                                       = undef,
  String[1]                   $audit_cfg_services_tag                                   = 'CFG_services',
  Optional[Boolean]           $audit_cfg_xinetd                                         = undef,
  String[1]                   $audit_cfg_xinetd_tag                                     = 'CFG_xinetd',
  Optional[Boolean]           $audit_yum                                                = undef,
  Optional[String[1]]         $audit_yum_tag                                            = undef,
  Optional[Boolean]           $audit_cfg_yum                                            = undef,
  String[1]                   $audit_cfg_yum_tag                                        = 'yum-config',
  Optional[Boolean]           $audit_yum_cmd                                            = undef,
  String[1]                   $audit_yum_cmd_tag                                        = 'package_changes',
  Optional[Boolean]           $audit_rpm_cmd                                            = undef,
  String[1]                   $audit_rpm_cmd_tag                                        = 'package_changes',
  Optional[Boolean]           $audit_ptrace                                             = undef,
  String[1]                   $audit_ptrace_tag                                         = 'paranoid',
  Optional[Boolean]           $audit_personality                                        = undef,
  String[1]                   $audit_personality_tag                                    = 'paranoid',
  Optional[Boolean]           $audit_passwd_cmds                                        = undef,
  String[1]                   $audit_passwd_cmds_tag                                    = 'privileged-passwd',
  Optional[Boolean]           $audit_priv_cmds                                          = undef,
  String[1]                   $audit_priv_cmds_tag                                      = 'privileged-priv_change',
  Optional[Boolean]           $audit_postfix_cmds                                       = undef,
  String[1]                   $audit_postfix_cmds_tag                                   = 'privileged-postfix',
  Optional[Boolean]           $audit_ssh_keysign_cmd                                    = undef,
  String[1]                   $audit_ssh_keysign_cmd_tag                                = 'privileged-ssh',
  Optional[Boolean]           $audit_suspicious_apps                                    = undef,
  String[1]                   $audit_suspicious_apps_tag                                = 'suspicious_apps',
  Auditd::PathList            $audit_suspicious_apps_list,                              # data in modules
  Optional[Boolean]           $audit_systemd                                            = undef,
  String[1]                   $audit_systemd_tag                                        = 'systemd',
  Optional[Boolean]           $audit_crontab_cmd                                        = undef,
  String[1]                   $audit_crontab_cmd_tag                                    = 'privileged-cron',
  Optional[Boolean]           $audit_pam_timestamp_check_cmd                            = undef,
  String[1]                   $audit_pam_timestamp_check_cmd_tag                        = 'privileged-pam',
  Auditd::EntryList           $basic_root_audit_syscalls,                               # data in modules
  Auditd::EntryList           $aggressive_root_audit_syscalls,                          # data in modules
  Auditd::EntryList           $insane_root_audit_syscalls                               # data in modules
) {
  assert_private()

  if $audit_sudoers != undef {
    deprecation("${name}::audit_sudoers",
    "'${name}::audit_sudoers' is deprecated. Use '${name}::audit_cfg_sudoers' instead")
    $_audit_cfg_sudoers = $audit_sudoers
  } else {
    $_audit_cfg_sudoers = $audit_cfg_sudoers
  }

  if $audit_sudoers_tag != undef {
    deprecation("${name}::audit_sudoers_tag",
    "'${name}::audit_sudoers_tag' is deprecated. Use '${name}::audit_cfg_sudoers_tag' instead")
    $_audit_cfg_sudoers_tag = $audit_sudoers_tag
  } else {
    $_audit_cfg_sudoers_tag = $audit_cfg_sudoers_tag
  }

  if $audit_grub != undef {
    deprecation("${name}::audit_grub",
    "'${name}::audit_grub' is deprecated. Use '${name}::audit_cfg_grub' instead")
    $_audit_cfg_grub = $audit_grub
  } else {
    $_audit_cfg_grub = $audit_cfg_grub
  }

  if $audit_grub_tag != undef {
    deprecation("${name}::audit_grub_tag",
    "'${name}::audit_grub_tag' is deprecated. Use '${name}::audit_cfg_grub_tag' instead")
    $_audit_cfg_grub_tag = $audit_grub_tag
  } else {
    $_audit_cfg_grub_tag = $audit_cfg_grub_tag
  }

  if $audit_yum != undef {
    deprecation("${name}::audit_yum",
    "'${name}::audit_yum' is deprecated. Use '${name}::'audit_cfg_yum instead")
    $_audit_cfg_yum = $audit_yum
  } else {
    $_audit_cfg_yum = $audit_cfg_yum
  }

  if $audit_yum_tag != undef {
    deprecation("${name}::audit_yum_tag",
    "'${name}::audit_yum_tag' is deprecated. Use '${name}::'audit_cfg_yum_tag instead")
    $_audit_cfg_yum_tag = $audit_yum_tag
  } else {
    $_audit_cfg_yum_tag = $audit_cfg_yum_tag
  }

  $_short_name = 'simp'
  $_idx = auditd::get_array_index($_short_name, $auditd::config::profiles)
  $_path = "/etc/audit/rules.d/50_${_idx}_${_short_name}_base.rules"

  # The syscalls share one rule, so an absent entry is left out of its -S list.
  $_su_root_syscalls = join(auditd::list_entries({
    'basic'      => $basic_root_audit_syscalls,
    'aggressive' => $aggressive_root_audit_syscalls,
    'insane'     => $insane_root_audit_syscalls,
  }[$root_audit_level]).filter |$_syscall, $ensure| { $ensure == 'present' }.keys, ',')

  $_grub_rules = $facts['grub_version'] ? {
    undef   => [],
    default => (versioncmp($facts['grub_version'], '2') < 0) ? {
      true    => ['-w /boot/grub/grub.conf -p wa'],
      default => ['-w /etc/grub.d -p wa'],
    },
  }

  $_systemd_rules = ('systemd' in $facts['init_systems']) ? {
    true    => ['-w /bin/systemctl -p x', '-w /usr/bin/systemctl -p x', '-w /etc/systemd/ -p wa'],
    default => [],
  }

  # The 32-bit API is only suspicious on a 64-bit host.
  $_audit_32bit_operations = $facts['os']['hardware'] ? {
    'x86_64' => $audit_32bit_operations,
    default  => undef,
  }

  # In the order the rules were written before 11.0.0. The kernel records the
  # key of the first rule an event matches, so for rules that overlap, order
  # decides which tag an event gets: the selinux command rules, for example,
  # must come before the xattr rules.
  $_all_toggles = [
    ['audit_32bit_operations', $_audit_32bit_operations, $audit_32bit_operations_tag, [
      '-a always,exit -F arch=b32 -S all',
    ], { 'key_option' => '-F key=' }],
    ['audit_network_ipv4_accept', $audit_network_ipv4_accept, $audit_network_ipv4_accept_tag, [
      '-a always,exit -F arch=b64 -S accept -F a0=2',
    ], { 'key_option' => '-F key=' }],
    ['audit_network_ipv6_accept', $audit_network_ipv6_accept, $audit_network_ipv6_accept_tag, [
      '-a always,exit -F arch=b64 -S accept -F a0=10',
    ], { 'key_option' => '-F key=' }],
    ['audit_network_ipv4_connect', $audit_network_ipv4_connect, $audit_network_ipv4_connect_tag, [
      '-a always,exit -F arch=b64 -S connect -F a0=2',
      '-a always,exit -F arch=b32 -S connect -F a0=2',
    ], { 'key_option' => '-F key=' }],
    ['audit_network_ipv6_connect', $audit_network_ipv6_connect, $audit_network_ipv6_connect_tag, [
      '-a always,exit -F arch=b64 -S connect -F a0=10',
      '-a always,exit -F arch=b32 -S connect -F a0=10',
    ], { 'key_option' => '-F key=' }],
    ['audit_unsuccessful_file_operations', $audit_unsuccessful_file_operations, $audit_unsuccessful_file_operations_tag, [
      '-a always,exit -F arch=b64 -S creat,mkdir,mknod,link,symlink,mkdirat,mknodat,linkat,symlinkat,openat,open_by_handle_at,open,close,rename,renameat,truncate,ftruncate,rmdir,unlink,unlinkat -F exit=-EACCES',
      '-a always,exit -F arch=b64 -S creat,mkdir,mknod,link,symlink,mkdirat,mknodat,linkat,symlinkat,openat,open_by_handle_at,open,close,rename,renameat,truncate,ftruncate,rmdir,unlink,unlinkat -F exit=-EPERM',
      '-a always,exit -F arch=b32 -S creat,mkdir,mknod,link,symlink,mkdirat,mknodat,linkat,symlinkat,openat,open_by_handle_at,open,close,rename,renameat,truncate,ftruncate,rmdir,unlink,unlinkat -F exit=-EACCES',
      '-a always,exit -F arch=b32 -S creat,mkdir,mknod,link,symlink,mkdirat,mknodat,linkat,symlinkat,openat,open_by_handle_at,open,close,rename,renameat,truncate,ftruncate,rmdir,unlink,unlinkat -F exit=-EPERM',
      '-a always,exit -F perm=a -F exit=-EACCES',
      '-a always,exit -F perm=a -F exit=-EPERM',
    ]],
    ['audit_passwd_cmds', $audit_passwd_cmds, $audit_passwd_cmds_tag, [
      '-a always,exit -F path=/usr/bin/passwd -F perm=x',
      '-a always,exit -F path=/bin/passwd -F perm=x',
      '-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x',
      '-a always,exit -F path=/sbin/unix_chkpwd -F perm=x',
      '-a always,exit -F path=/usr/bin/gpasswd -F perm=x',
      '-a always,exit -F path=/bin/gpasswd -F perm=x',
      '-a always,exit -F path=/usr/bin/chage -F perm=x',
      '-a always,exit -F path=/bin/chage -F perm=x',
      '-a always,exit -F path=/usr/sbin/userhelper -F perm=x',
      '-a always,exit -F path=/sbin/userhelper -F perm=x',
    ]],
    ['audit_priv_cmds', $audit_priv_cmds, $audit_priv_cmds_tag, [
      '-a always,exit -F path=/usr/bin/su -F perm=x',
      '-a always,exit -F path=/bin/su -F perm=x',
      '-a always,exit -F path=/usr/bin/sudo -F perm=x',
      '-a always,exit -F path=/bin/sudo -F perm=x',
      '-a always,exit -F path=/usr/bin/newgrp -F perm=x',
      '-a always,exit -F path=/bin/newgrp -F perm=x',
      '-a always,exit -F path=/usr/bin/chsh -F perm=x',
      '-a always,exit -F path=/bin/chsh -F perm=x',
      '-a always,exit -F path=/usr/bin/sudoedit -F perm=x',
      '-a always,exit -F path=/bin/sudoedit -F perm=x',
    ]],
    ['audit_postfix_cmds', $audit_postfix_cmds, $audit_postfix_cmds_tag, [
      '-a always,exit -F path=/usr/sbin/postdrop -F perm=x',
      '-a always,exit -F path=/sbin/postdrop -F perm=x',
      '-a always,exit -F path=/usr/sbin/postqueue -F perm=x',
      '-a always,exit -F path=/sbin/postqueue -F perm=x',
    ]],
    ['audit_ssh_keysign_cmd', $audit_ssh_keysign_cmd, $audit_ssh_keysign_cmd_tag, [
      '-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x',
    ]],
    ['audit_crontab_cmd', $audit_crontab_cmd, $audit_crontab_cmd_tag, [
      '-a always,exit -F path=/usr/bin/crontab -F perm=x',
      '-a always,exit -F path=/bin/crontab -F perm=x',
    ]],
    ['audit_pam_timestamp_check_cmd', $audit_pam_timestamp_check_cmd, $audit_pam_timestamp_check_cmd_tag, [
      '-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x',
      '-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x',
    ]],
    ['audit_selinux_cmds', $audit_selinux_cmds, $audit_selinux_cmds_tag, [
      '-a always,exit -F path=/usr/sbin/semanage -F perm=x',
      '-a always,exit -F path=/sbin/semanage -F perm=x',
      '-a always,exit -F path=/usr/sbin/setsebool -F perm=x',
      '-a always,exit -F path=/sbin/setsebool -F perm=x',
      '-a always,exit -F path=/usr/bin/chcon -F perm=x',
      '-a always,exit -F path=/bin/chcon -F perm=x',
      '-a always,exit -F path=/usr/sbin/setfiles -F perm=x',
      '-a always,exit -F path=/sbin/setfiles -F perm=x',
    ]],
    ['audit_chown', $audit_chown, $audit_chown_tag, [
      '-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown',
      '-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown',
    ]],
    ['audit_chmod', $audit_chmod, $audit_chmod_tag, [
      '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat',
      '-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat',
    ]],
    ['audit_attr', $audit_attr, $audit_attr_tag, [
      '-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr',
      '-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr',
    ]],
    ['audit_rename_remove', $audit_rename_remove, $audit_rename_remove_tag, [
      '-a always,exit -F arch=b64 -S rename,renameat,rmdir,unlink,unlinkat -F perm=x',
      '-a always,exit -F arch=b32 -S rename,renameat,rmdir,unlink,unlinkat -F perm=x',
    ]],
    # Matched on any -S list, so a changed root_audit_level replaces these.
    ['audit_su_root_activity', $audit_su_root_activity, $audit_su_root_activity_tag, [
      "-a always,exit -F arch=b64 -F auid!=0 -F uid=0 -S ${_su_root_syscalls}",
      "-a always,exit -F arch=b32 -F auid!=0 -F uid=0 -S ${_su_root_syscalls}",
    ], { 'any_syscalls' => true }],
    ['audit_suid_sgid', $audit_suid_sgid, $audit_suid_sgid_tag, [
      '-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0',
      '-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0',
      '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0',
      '-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0',
    ]],
    ['audit_kernel_modules', $audit_kernel_modules, $audit_kernel_modules_tag, [
      '-w /usr/bin/kmod -p x',
      '-w /bin/kmod -p x',
      '-w /usr/sbin/insmod -p x',
      '-w /sbin/insmod -p x',
      '-w /usr/sbin/rmmod -p x',
      '-w /sbin/rmmod -p x',
      '-w /usr/sbin/modprobe -p x',
      '-w /sbin/modprobe -p x',
      '-a always,exit -F arch=b64 -S create_module,init_module,finit_module,delete_module',
      '-a always,exit -F arch=b32 -S create_module,init_module,finit_module,delete_module',
    ]],
    ['audit_time', $audit_time, $audit_time_tag, [
      '-a always,exit -F arch=b64 -S adjtimex,settimeofday',
      '-a always,exit -F arch=b64 -S clock_settime -F a0=0x0',
      '-a always,exit -F arch=b32 -S adjtimex,stime,settimeofday',
      '-a always,exit -F arch=b32 -S clock_settime -F a0=0x0',
      '-w /etc/localtime -p wa',
    ]],
    ['audit_locale', $audit_locale, $audit_locale_tag, [
      '-a always,exit -F arch=b64 -S sethostname,setdomainname',
      '-a always,exit -F arch=b32 -S sethostname,setdomainname',
      '-w /etc/issue -p wa',
      '-w /etc/issue.net -p wa',
      '-w /etc/hosts -p wa',
      '-w /etc/hostname -p wa',
      '-w /etc/sysconfig/network -p wa',
      '-a always,exit -F dir=/etc/NetworkManager/ -F perm=wa',
    ]],
    ['audit_mount', $audit_mount, $audit_mount_tag, [
      '-a always,exit -F arch=b64 -S mount,umount2',
      '-a always,exit -F arch=b32 -S mount,umount,umount2',
      '-a always,exit -F arch=b64 -F path=/usr/bin/mount',
      '-a always,exit -F arch=b64 -F path=/bin/mount',
      '-a always,exit -F arch=b32 -F path=/usr/bin/mount',
      '-a always,exit -F arch=b32 -F path=/bin/mount',
      '-a always,exit -F path=/usr/bin/umount -F perm=x',
      '-a always,exit -F path=/bin/umount -F perm=x',
    ]],
    ['audit_umask', $audit_umask, $audit_umask_tag, [
      '-a always,exit -F arch=b64 -S umask',
      '-a always,exit -F arch=b32 -S umask',
    ]],
    ['audit_local_account', $audit_local_account, $audit_local_account_tag, [
      '-w /etc/passwd -p wa',
      '-w /etc/group -p wa',
      '-w /etc/gshadow -p wa',
      '-w /etc/shadow -p wa',
      '-w /etc/security/opasswd -p wa',
      '-w /etc/passwd- -p wa',
      '-w /etc/group- -p wa',
      '-w /etc/shadow- -p wa',
    ]],
    ['audit_selinux_policy', $audit_selinux_policy, $audit_selinux_policy_tag, [
      '-w /etc/selinux/ -p wa',
      '-w /usr/share/selinux/ -p wa',
    ]],
    ['audit_login_files', $audit_login_files, $audit_login_files_tag, [
      '-w /var/log/tallylog -p wa',
      '-w /var/run/faillock -p wa',
      '-w /var/log/lastlog -p wa',
      '-w /var/log/faillog -p wa',
    ]],
    ['audit_session_files', $audit_session_files, $audit_session_files_tag, [
      '-w /var/run/utmp -p wa',
      '-w /var/log/btmp -p wa',
      '-w /var/log/wtmp -p wa',
    ]],
    ['audit_cfg_sudoers', $_audit_cfg_sudoers, $_audit_cfg_sudoers_tag, [
      '-w /etc/sudoers -p wa',
      '-w /etc/sudoers.d/ -p wa',
    ]],
    ['audit_auditd_cmds', $audit_auditd_cmds, $audit_auditd_cmds_tag,
      auditd::list_entries($audit_auditd_cmds_list).map |$cmd, $ensure| { { 'rule' => "-w ${cmd} -p x", 'ensure' => $ensure } },
    ],
    ['audit_systemd', $audit_systemd, $audit_systemd_tag, $_systemd_rules],
    ['audit_suspicious_apps', $audit_suspicious_apps, $audit_suspicious_apps_tag,
      auditd::list_entries($audit_suspicious_apps_list).map |$app, $ensure| { { 'rule' => "-w ${app} -p x", 'ensure' => $ensure } },
    ],
    ['audit_cfg_grub', $_audit_cfg_grub, $_audit_cfg_grub_tag, $_grub_rules],
    ['audit_cfg_sys', $audit_cfg_sys, $audit_cfg_sys_tag, [
      '-w /etc/default -p wa',
      '-w /etc/exports -p wa',
      '-w /etc/fstab -p wa',
      '-w /etc/host.conf -p wa',
      '-w /etc/hosts.allow -p wa',
      '-w /etc/hosts.deny -p wa',
      '-w /etc/initlog.conf -p wa',
      '-w /etc/inittab -p wa',
      '-w /etc/krb5.conf -p wa',
      '-w /etc/ld.so.conf -p wa',
      '-w /etc/ld.so.conf.d -p wa',
      '-w /etc/login.defs -p wa',
      '-w /etc/modprobe.conf.d -p wa',
      '-w /etc/modprobe.d/00_simp_blacklist.conf -p wa',
      '-w /etc/nsswitch.conf -p wa',
      '-w /etc/aliases -p wa',
      '-w /etc/at.deny -p wa',
      '-w /etc/rc.d/init.d -p wa',
      '-w /etc/rc.local -p wa',
      '-w /etc/rc.sysinit -p wa',
      '-w /etc/resolv.conf -p wa',
      '-w /etc/securetty -p wa',
      '-w /etc/snmp/snmpd.conf -p wa',
      '-w /etc/ssh/sshd_config -p wa',
      '-w /etc/sysconfig -p wa',
      '-w /etc/sysctl.conf -p wa',
      '-w /lib/firmware/microcode.dat -p wa',
      '-w /var/spool/at -p wa',
    ]],
    ['audit_cfg_cron', $audit_cfg_cron, $audit_cfg_cron_tag, [
      '-w /etc/cron.d -p wa',
      '-w /etc/anacrontab -p wa',
      '-w /etc/cron.daily -p wa',
      '-w /etc/cron.deny -p wa',
      '-w /etc/cron.hourly -p wa',
      '-w /etc/cron.monthly -p wa',
      '-w /etc/cron.weekly -p wa',
      '-w /etc/crontab -p wa',
    ]],
    ['audit_cfg_shell', $audit_cfg_shell, $audit_cfg_shell_tag, [
      '-w /etc/csh.cshrc -p wa',
      '-w /etc/bashrc -p wa',
      '-w /etc/csh.login -p wa',
      '-w /etc/profile -p wa',
      '-w /etc/shells -p wa',
    ]],
    ['audit_cfg_pam', $audit_cfg_pam, $audit_cfg_pam_tag, [
      '-w /etc/pam.d -p wa',
      '-w /etc/pam_smb.conf -p wa',
    ]],
    ['audit_cfg_security', $audit_cfg_security, $audit_cfg_security_tag, [
      '-w /etc/security -p wa',
    ]],
    ['audit_cfg_services', $audit_cfg_services, $audit_cfg_services_tag, [
      '-w /etc/services -p wa',
    ]],
    ['audit_cfg_xinetd', $audit_cfg_xinetd, $audit_cfg_xinetd_tag, [
      '-w /etc/xinetd.conf -p wa',
      '-w /etc/xinetd.d -p wa',
    ]],
    ['audit_cfg_yum', $_audit_cfg_yum, $_audit_cfg_yum_tag, [
      '-w /etc/yum -p wa',
      '-w /etc/yum.conf -p wa',
      '-w /etc/yum.repos.d -p wa',
    ]],
    ['audit_yum_cmd', $audit_yum_cmd, $audit_yum_cmd_tag, [
      '-w /usr/bin/yum -p x',
      '-w /bin/yum -p x',
    ]],
    ['audit_rpm_cmd', $audit_rpm_cmd, $audit_rpm_cmd_tag, [
      '-w /usr/bin/rpm -p x',
      '-w /bin/rpm -p x',
    ]],
    # The specific ptrace rules must come before the general one.
    ['audit_ptrace', $audit_ptrace, $audit_ptrace_tag, [
      ['-a always,exit -F arch=b64 -S ptrace -F a0=0x4', "${audit_ptrace_tag}_code_injection"],
      ['-a always,exit -F arch=b64 -S ptrace -F a0=0x5', "${audit_ptrace_tag}_data_injection"],
      ['-a always,exit -F arch=b64 -S ptrace -F a0=0x6', "${audit_ptrace_tag}_register_injection"],
      '-a always,exit -F arch=b64 -S ptrace',
      ['-a always,exit -F arch=b32 -S ptrace -F a0=0x4', "${audit_ptrace_tag}_code_injection"],
      ['-a always,exit -F arch=b32 -S ptrace -F a0=0x5', "${audit_ptrace_tag}_data_injection"],
      ['-a always,exit -F arch=b32 -S ptrace -F a0=0x6', "${audit_ptrace_tag}_register_injection"],
      '-a always,exit -F arch=b32 -S ptrace',
    ]],
    ['audit_personality', $audit_personality, $audit_personality_tag, [
      '-a always,exit -F arch=b64 -S personality',
      '-a always,exit -F arch=b32 -S personality',
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
        *            => pick($t[4], {}),
      }
    }
  }
}
