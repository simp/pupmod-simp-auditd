[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-auditd.svg)](https://travis-ci.org/simp/pupmod-simp-dummy) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)

#### Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Setup - The basics of getting started with auditd](#setup)
    * [What auditd affects](#what-dummy-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with auditd](#beginning-with-dummy)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)
      * [Acceptance Tests - Beaker env variables](#acceptance-tests)

## Overview

This module manages the Audit daemon, kernel parameters, and related subsystems.

## This is a SIMP module
This module is a component of the [System Integrity Management Platform](https://github.com/NationalSecurityAgency/SIMP), a compliance management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP) and visit our [developer wiki](https://simp-project.atlassian.net/wiki/display/SD/SIMP+Development+Home).

This module is optimally designed for use within a larger SIMP ecosystem, but it can be used independently:
* When included within the SIMP ecosystem, security compliance settings will be managed from the Puppet server.
* In the future, all SIMP-managed security subsystems will be disabled by default and must be explicitly opted into by administrators.  Please review simp_options for details.

## Module Description

You can use this module for the management of all components of auditd including configuration, service management, kernel parameters, and custom rule sets.

By default, a rule set is provided that should meet a reasonable set of operational goals for most environments.

The `audit` kernel parameter may optionally be managed independently of the rest of the module using the `::auditd::config::grub` class.

## Setup

### What auditd affects

* The `audit` kernel parameter
  * NOTE: This will be applied to *all* kernels in your standard grub configuration
* The auditd service
* The audid configuration in /etc/auditd.conf
* The auditd rules in /etc/audit/rules.d
* The audispd configuration in /etc/audisp/audispd.conf
* The audispd `syslog` configuration in /etc/audisp/plugins.d/syslog.conf

## Usage

### Basic Usage

```puppet
# Set up auditd with the default settings
# A message will be printed indicating that you need to reboot for this option
# to take full effect at each Puppet run until you reboot your system.

include '::auditd'
```

### Disabling Auditd

auditd::at_boot : false

#### Changing Key Values
```puppet
# To override the default values included in the module, you can either
# include new values for the keys at the time that the classes are declared:

class { '::auditd':
  ignore_failures => true
  log_group       => 'root'
  flush           => 'INCREMENTAL'
}

# or, for a subclass:

class { '::auditd::config::audisp': 
  max_restarts => 10
  name_format  => 'USER'
}
```

#### Manifest

```puppet
# Be aware that, on a SIMP system, svckill will disable the actual audit daemon
# if you do not manage it. Otherwise, you need to do this independently if
# necessary.

include '::auditd'
```

## Reference

### Classes

#### Public Classes
* `auditd`
* `auditd::config`
* `auditd::config::audisp`
* `auditd::config::grub`
* `auditd::config::audisp::syslog`
* `auditd::config::audit_profiles::simp`

#### Private Classes
* `auditd::install`
* `auditd::service`
* `auditd::config::audisp_service`
* `auditd::config::logging`

#### Defined Types
* `auditd::rule`

## Parameters

### auditd

This is the main class for the auditd module. 

##### `admin_space_left`:
  Description
  * Valid Options: Integer
  * Default: 50

##### `admin_space_left_action`:

  * Valid Options: Integer[0]
  * Default: 'SUSPEND'

##### `action_mail_acct`:

  * Valid Options: String
  * Default: 'root'

##### `at_boot`:

  If true, enable auditing at boot time.
  * Valid Options: Boolean
  * Default: true

##### `buffer_size`:

  * Valid Options: Integer
  * Default: 16384

##### `default_audit_profile`:

  Sets the default audit rules of the system to the given profile.
  * Valid Types: 'simp', Boolean
  * Default: 'simp'

##### `disk_error_action`:

  * Valid Options: Auditd::DiskErrorAction
  * Default: 'SUSPEND'

##### `disk_full_action`:

  * Valid Options: Auditd::DiskFullAction
  * Default: 'SUSPEND'

##### `dispatcher`:

  * Valid Options: Stdlib::Absolutepath
  * Default: '/sbin/audispd'

##### `disp_qos`:

  * Valid Options: 'lossy','lossless'
  * Default: 'lossy'

##### `enable`:

  If true, auditing is enabled.
  * Valid Options: Boolean
  * Default: true

##### `failure_mode`:

  * Valid Options: Integer[0]
  * Default: 1

##### `flush`:

  * Valid Options: Auditd::Flush
  * Default: 'INCREMENTAL'

##### `freq`:

  * Valid Options: Integer[0]
  * Default: 20

##### `ignore_failures`:

  * Valid Options: Boolean
  * Default: true

##### `immutable`:

  Determines if the configuration should be immutable. Be aware that if configuration is set to immutable, you will not be able to change audit rules without rebooting.
  * Valid Options: Boolean
  * Default: false

##### `lname`:

  This parameter is an alias for the ``name`` variable in the man pages. Because $name is reserved in the Puppet language, $lname is used to represent the ``name`` key in auditd.conf.
  * Valid Options: String
  * Default: $facts['fqdn']

##### `log_group`:

  * Valid Options: String
  * Default: 'root'

##### `log_format`:

  * Valid Types: 'RAW','NOLOG'
  * Default: 'RAW'

##### `log_file`:

  * Valid Options: Stdlib::Absolutepath
  * Default: '/var/log/audit/audit.log'

##### `max_log_file_action`:

  * Valid Options: Auditd::DiskFullAction
  * Default: 'ROTATE'

##### `max_log_file`:

  * Valid Options: Integer[0]
  * Default: 24

##### `name_format`:

  * Valid Options: Auditd::NameFormat
  * Default: 'USER'

##### `num_logs`:

  * Valid Options: Integer[0]
  * Default: 5

##### `package_name`:

  Name of the auditd package.
  * Valid Options: String
  * Default: audit (Redhat OS family)

##### `package_ensure`:

  * Valid Options: String
  * Default: 'latest'

##### `priority_boost`:

  * Valid Options: Integer[0]
  * Default: 3

##### `rate`:

  * Valid Options: Integer[0]
  * Default: 0

##### `root_audit_level`:

  Determines the level of auditing for su-root activity. Be aware that setting this to values higher than `basic` my overwhelm or system / log server. Options can be `basic`, `aggressive`, `insane`. (Basic: Safe, should not follow program execution outside of base app; Aggressive: adds execve; Insane: Adds fork, vfork, write, chown, creat, link, mkdir, rmdir)
  * Valid Types: 'basic','aggressive','insane'
  * Default: 'basic'

##### `space_left_action`:

  * Valid Options: Auditd::SpaceLeftAction
  * Default: 'SUSPEND'

##### `space_left`:

  * Valid Options: Integer[0]
  * Default: 75

##### `service_name`:

  Name of the auditd service
  * Valid Options: String
  * Default: auditd (Redhat OS family)

##### `syslog`:

  If true, set up audispd to send logs via syslog.
  * Valid Options: Boolean
  * Default: Lookup simp_options::syslog, if `simp_options` not present on system, default to false.

##### `uid_min`:

  Minimum UID for human users of the system. Logs generated by users lower than this number will be ignored unless $absolute is set to first in `auditd::add_rule`
  * Valid Options: Integer[0]
  * Default: $facts['uid_min']

### auditd::config

`auditd::config` sets values in the auditd.conf file (usually found at `/etc/audit/auditd.conf`). There is also space here for declaring a default set of audit rules (via the default_audit_profile option). Parameters listed below that have no description have a one-to-one correspondance with the documentation in the auditd man pages. Specifically see pages 5 (auditd.conf) and 8 (auditctl). Parameters warranting further explanation are appended with a description.


##### `log_file`:

  * Valid Options: Stdlib::Absolutepath
  * Default: '/var/log/audit/audit.log'

##### `log_format`:

  * Valid Types: 'RAW','NOLOG'
  * Default: 'RAW'

##### `log_group`:

  * Valid Options: String
  * Default: 'root'

##### `priority_boost`:

  * Valid Options: Integer[0]
  * Default: 3

##### `flush`:

  * Valid Options: Auditd::Flush
  * Default: 'INCREMENTAL'

##### `freq`:

  * Valid Options: Integer[0]
  * Default: 20

##### `num_logs`:

  * Valid Options: Integer[0]
  * Default: 5

##### `disp_qos`:

  * Valid Types: 'lossy','lossless'
  * Default: 'lossy'

##### `dispatcher`:

  * Valid Options: Stdlib::Absolutepath
  * Default: '/sbin/audispid'

##### `name_format`:

  * Valid Options: Auditd::NameFormat
  * Default: 'User'

##### `lname`:

  This parameter is an alias for the ``name`` variable in the man pages. Because $name is reserved in the Puppet language, $lname is used to represent the ``name`` key in auditd.conf.
  * Valid Options: String
  * Default: $facts['fqdn']

##### `max_log_file_action`:

  * Valid Options: Auditd::DiskFullAction
  * Default: 'ROTATE'

##### `max_log_file`:

  * Valid Options: Integer[0]
  * Default: 24

##### `space_left`:

  * Valid Options: Integer[0]
  * Default: 75

##### `space_left_action`:

  * Valid Options: Auditd::SpaceLeftAction
  * Default: 'SYSLOG'

##### `action_mail_acct`:

  * Valid Options: String
  * Default: 'root'

##### `admin_space_left`:

  * Valid Options: Integer
  * Default: 50

##### `admin_space_left_action`:

  * Valid Options: Auditd::SpaceLeftAction
  * Default: 'SUSPEND'

##### `disk_full_action`:

  * Valid Options: Auditd::DiskFullAction
  * Default: 'SUSPEND'

##### `disk_error_action`:

  * Valid Options: Auditd::DiskErrorAction
  * Default: 'SUSPEND'

##### `default_audit_profile`:

  * Valid Types: 'simp', Boolean
  * Default: 'simp'

### auditd::config::audisp

All parameters in this class are documented on page 5 of audispd.conf's man page. The execption is the $specific_name parameter, which maps to the audispd.conf `name` variable.

##### `q_depth`:

  * Valid Options: Integer
  * Default: 160

##### `overflow_action`:

  * Valid Options: Auditd::OverflowAction
  * Default: 'SYSLOG'

##### `priority_boost`:

  * Valid Options: Integer
  * Default: 4

##### `max_restarts`:

  * Valid Options: Integer
  * Default: 10

##### `name_format`:

  * Valid Options: Auditd::NameFormat
  * Default: 'USER'

##### `specific_name`:

  maps to `name` in audispd.conf, because $name is restricted in Puppet.
  * Valid Options: String
  * Default: $facts['fqdn']

### auditd::config::grub

The `auditd::config::grub` class controls if auditing is enabled at boot time.

##### `enable`:

  If true, audit at boot is enabled.
  * Valid Options: Boolean
  * Default: true

### auditd::config::audisp::syslog

The `auditd::config::audisp::syslog` class utilizes rsyslog to send audit records to a remote logging server. **This class REQUIRES the `pupmod-simp-rsyslog` module to be installed**. It is suggested that you read the headers in the manifest for this class if you intend to leverage this functionality.

##### `drop_audit_logs`:

  * Valid Options: Boolean
  * Default: true

##### `priority`:

  * Valid Options: Auditd::LogPriority
  * Default:

##### `facility`:

  'LOG_INFO'
  * Valid Options: Auditd::LogFacility
  * Default: 'LOG_LOCAL5'

### auditd::config::audit_profiles::simp

The `auditd::config::audit_profiles::simp` class is a set of audit rules that are configure to meet the general goals for SIMP. If you are running a SIMP system, you should be able to just use this profile to set appropriate defaults for many configuration options. The parameters available in this class are listed here, but because they have almost all have a one-to-one relationship with existing documentation for auditd, they are not documented here. You can find types and defaults for the params of this class in the manifest which defines it.

##### `log_file`
##### `num_logs`
##### `ignore_failures`
##### `buffer_size`
##### `failure_mode`
##### `rate`
##### `immutable`
##### `root_audit_level`
##### `uid_min`
##### `ignore_crond`
##### `ignore_errors`
##### `ignore_anonymous`
##### `ignore_system_services`
##### `audit_unsuccessful_file_operations`
##### `audit_unsuccessful_file_operations_tag`
##### `audit_chown`
##### `audit_chown_tag`
##### `audit_chmod`
##### `audit_chmod_tag`
##### `audit_attr`
##### `audit_attr_tag`
##### `audit_su_root_activity`
##### `audit_su_root_activity_tag`
##### `audit_suid_sgid`
##### `audit_suid_sgid_tag`
##### `audit_kernel_modules`
##### `audit_kernel_modules_tag`
##### `audit_time`
##### `audit_time_tag`
##### `audit_locale`
##### `audit_locale_tag`
##### `audit_mount`
##### `audit_mount_tag`
##### `audit_umask`
##### `audit_umask_tag`
##### `audit_local_account`
##### `audit_local_account_tag`
##### `audit_selinux_policy`
##### `audit_selinux_policy_tag`
##### `audit_login_files`
##### `audit_login_files_tag`
##### `audit_session_files`
##### `audit_session_files_tag`
##### `audit_sudoers`
##### `audit_sudoers_tag`
##### `audit_grub`
##### `audit_grub_tag`
##### `audit_cfg_sys`
##### `audit_cfg_sys_tag`
##### `audit_cfg_cron`
##### `audit_cfg_cron_tag`
##### `audit_cfg_shell`
##### `audit_cfg_shell_tag`
##### `audit_cfg_pam`
##### `audit_cfg_pam_tag`
##### `audit_cfg_security`
##### `audit_cfg_security_tag`
##### `audit_cfg_services`
##### `audit_cfg_services_tag`
##### `audit_cfg_xinetd`
##### `audit_cfg_xinetd_tag`
##### `audit_yum`
##### `audit_yum_tag`
##### `audit_ptrace`
##### `audit_ptrace_tag`
##### `audit_personality`
##### `audit_personality_tag`

### auditd::rule (defined type)

##### `absolute`:

  When set to true, ensures rules are added absolutely first or last depending on $first
  * Valid Options: Boolean
  * Default: false

##### `content`:

  The content of the rule to be added
  * Valid Options: String
  * Default: N/A

##### `first`:

  When set to true, prepend your custom rules. Otherwise, append. See $absolute
  * Valid Options: Boolean
  * Default: false

##### `name`:

  The unique identifier for this rule.
  * Valid Options: Boolean
  * Default: false


# Limitations

SIMP Puppet modules are generally intended to be used on a Redhat Enterprise Linux-compatible distribution such as EL6 and EL7.

## Development

Please see the [SIMP Contribution Guidelines](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP).

### Acceptance tests

To run the system tests, you need [Vagrant](https://www.vagrantup.com/) installed. Then, run:

```shell
bundle exec rake beaker:suites
```

Some environment variables may be useful:

```shell
BEAKER_debug=true
BEAKER_provision=no
BEAKER_destroy=no
BEAKER_use_fixtures_dir_for_modules=yes
```

* `BEAKER_debug`: show the commands being run on the STU and their output.
* `BEAKER_destroy=no`: prevent the machine destruction after the tests finish so you can inspect the state.
* `BEAKER_provision=no`: prevent the machine from being recreated. This can save a lot of time while you're writing the tests.
* `BEAKER_use_fixtures_dir_for_modules=yes`: cause all module dependencies to be loaded from the `spec/fixtures/modules` directory, based on the contents of `.fixtures.yml`.  The contents of this directory are usually populated by `bundle exec rake spec_prep`.  This can be used to run acceptance tests to run on isolated networks.
