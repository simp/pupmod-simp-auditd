[![License](https://img.shields.io/:license-apache-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/73/badge)](https://bestpractices.coreinfrastructure.org/projects/73)
[![Puppet Forge](https://img.shields.io/puppetforge/v/simp/auditd.svg)](https://forge.puppetlabs.com/simp/auditd)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/simp/auditd.svg)](https://forge.puppetlabs.com/simp/auditd)
[![Build Status](https://travis-ci.org/simp/pupmod-simp-auditd.svg)](https://travis-ci.org/simp/pupmod-simp-auditd)

#### Table of Contents

<!-- vim-markdown-toc GFM -->

* [Overview](#overview)
* [Breaking changes in 11.0.0](#breaking-changes-in-1100)
* [This is a SIMP module](#this-is-a-simp-module)
* [Module Description](#module-description)
* [Setup](#setup)
  * [Setup Requirements](#setup-requirements)
  * [What Auditd Affects](#what-auditd-affects)
  * [When changes take effect](#when-changes-take-effect)
* [Usage](#usage)
  * [Basic Usage](#basic-usage)
  * [Disabling Auditd](#disabling-auditd)
  * [Changing Key Values](#changing-key-values)
  * [Understanding Auditd Profiles](#understanding-auditd-profiles)
    * [Stacking Profiles](#stacking-profiles)
    * [The Custom Profile](#the-custom-profile)
      * [Override All Other Profiles](#override-all-other-profiles)
      * [Prepend Before the SIMP Profile](#prepend-before-the-simp-profile)
      * [Append After the SIMP and STIG Profiles](#append-after-the-simp-and-stig-profiles)
    * [The Built-in Profile](#the-built-in-profile)
      * [Disabling All SIMP-provided Profiles](#disabling-all-simp-provided-profiles)
      * [Enabling Sample Rulesets with Built-in Profile](#enabling-sample-rulesets-with-built-in-profile)
      * [Configuring Complete Rulesets with Built-in Profile](#configuring-complete-rulesets-with-built-in-profile)
  * [Adding One-Off Rules](#adding-one-off-rules)
    * [Adding Regular Filter Rules](#adding-regular-filter-rules)
    * [Prepend and Drop Everything From a User](#prepend-and-drop-everything-from-a-user)
* [Development](#development)
  * [Acceptance tests](#acceptance-tests)

<!-- vim-markdown-toc -->

## Overview

This module manages the Audit daemon, kernel parameters, and related subsystems.

## Breaking changes in 11.0.0

**Including this class no longer configures anything.** Before 11.0.0, `include 'auditd'`
installed the package, replaced your kernel audit rules, purged `/etc/audit/rules.d`,
rewrote `auditd.conf`, took ownership of `/etc/audit` and `/var/log/audit`, started and
enabled the service, and added `audit=1` to the kernel command line. It now installs the
package and stops there. Every other resource is declared only when a parameter asks for
it, and those parameters default to `undef`, `false` or `[]`.

If you are a SIMP user, apply the `simp:defaults` compliance profile and you get the old
behavior back. If you are not, set what you want explicitly.

### What changes even with `simp:defaults` applied

* `/etc/audit/audit-stop.rules` and the `audisp-*.conf` files are no longer deleted. The
  recursive purge of `/etc/audit` is gone, so `rpm -V audit` comes back clean.
* `/etc/audit` keeps the mode the package ships (`0750`) rather than being tightened
  to `0700`.
* `auditd.conf` is edited key by key instead of being rendered from a template, so
  package comments and the keys this module has no opinion about (`use_libwrap`,
  `tcp_*`, `transport`, `krb5_principal`, `distribute_network`,
  `end_of_event_timeout`) stay in the file at their packaged values. The effective
  daemon configuration is unchanged, because those packaged values match the
  compiled-in defaults the daemon used before. Keys keep their packaged position;
  a key missing from the file is appended. That matters for `verify_email`, which
  auditd only honours if it precedes `action_mail_acct`. Every supported package
  ships it in that position, so only a file it was removed from by hand is affected.
* On auditd 3 and later, `/etc/audit/plugins.d/syslog.conf` is edited key by key
  instead of being rendered from a template. Only `active` and `args` are written,
  plus `path` and `type` when set explicitly; the rest keeps the packaged values,
  which match what the template wrote. auditd 2's `audispd.conf` is unchanged.

### What changes if you do not apply a profile

* A bare `include 'auditd'` installs the package. Service state, rules, GRUB,
  `auditd.conf` and the log directory are left exactly as the package left them.
* `auditd::enable` is deprecated. `true` prints a notice and does nothing else;
  `false` prints a notice and implies a stopped, disabled service with
  `at_boot => false`, but no longer stands the rest of the module down.
  `auditd::default_audit_profile` is likewise deprecated in favour of
  `auditd::default_audit_profiles`.
* Setting one `auditd.conf` parameter now changes exactly that one key. The
  exception is `auditd::admin_space_left`, which also writes the `space_left` derived
  from it unless `auditd::space_left` is set.
* `auditd::space_left` defaults to `undef` rather than
  `auditd::calculate_space_left($admin_space_left)`. It is still derived from
  `auditd::admin_space_left` when that is set, so the two keys are written together;
  unset, neither is written.
* `auditd::config_group` no longer defaults to `auditd::log_group`. The two govern
  different things -- who may read the audit *logs* versus who may read the audit
  *configuration* -- and are set independently now. Unset, the configuration files
  fall back to group `root`.
* Changing `auditd::default_audit_profiles` from `['simp']` to `['stig']` without
  `auditd::purge_auditd_rules: true` leaves the old `50_0_simp_base.rules` on disk.
  The purge used to remove it for you.
* **Without `auditd::purge_auditd_rules: true`, the packaged
  `/etc/audit/rules.d/audit.rules` overrides `auditd::buffer_size` and
  `auditd::failure_mode`.** The `audit` package drops that file (`-D`, `-b 8192`,
  `-f 1`) into an empty `rules.d`. `augenrules` lets the later-sorting file win
  on a duplicated `-b` or `-f`, and `audit.rules` sorts after every file this
  module writes. The purge used to remove it for you; set
  `auditd::purge_auditd_rules: true` or delete the file yourself.
* `00_head.rules`, `05_default_drop.rules` and `99_tail.rules` are edited line
  by line instead of rendered whole. Each line follows its parameter: unset
  leaves whatever is in the file, `false` (or `'absent'` for a number) removes
  it, and a value writes it. A partial compliance profile therefore never
  reverts what an earlier one applied. This covers `auditd::buffer_size`,
  `auditd::backlog_wait_time`, `auditd::failure_mode`, `auditd::rate`,
  `auditd::loginuid_immutable`, `auditd::ignore_errors`,
  `auditd::ignore_failures`, `auditd::immutable`, `auditd::target_selinux_types`
  and the `auditd::ignore_*` drops.
* `auditd::immutable` defaults to `undef` rather than `false`. `simp:defaults`
  sets `false`.
* `auditd::target_selinux_types` entries must be SELinux type names
  (`[a-z0-9_]+_t`). A Hash of type to `ensure` can also remove one.
* A new `00_head.rules` is seeded once with `-D` and the packaged `-b 8192`,
  which the purge removes. After that it is only edited in place.
  `simp:defaults` sets `-b 16384`.
* With `auditd::ignore_failures` unset, the `simp` and `stig` profiles write
  `-c`. They watch paths that may not exist, such as `/etc/snmp/snmpd.conf`, and
  without `-c` the kernel stops loading at the first rejected rule and silently
  drops every rule after it. Set `auditd::ignore_failures: false` to opt out.
* `auditd::config::audisp::syslog::pkg_name` is a required `String[1]` supplied by the
  module data. Setting it to `~` used to skip the `audispd-plugins` package; it now fails
  the catalogue.

## This is a SIMP module

This module is a component of the [System Integrity Management Platform](https://simp-project.com),
a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

This module is optimally designed for use within a larger SIMP ecosystem, but it can be used independently:
* When included within the SIMP ecosystem, security compliance settings will be
  managed from the Puppet server.
* If used independently, all SIMP-managed security subsystems will be disabled by
  default and must be explicitly opted into by administrators.  Please review
  ``simp_options`` for details.

## Module Description

You can use this module for the management of all components of auditd
including configuration, service management, kernel parameters, and custom rule
sets. Each of those is opted into separately; see
[Breaking changes in 11.0.0](#breaking-changes-in-1100).

A rule set meeting a reasonable set of operational goals for most environments
is available as the `simp` audit profile, and is what the `simp:defaults`
compliance profile selects. It is not applied unless you ask for it.

The `audit` kernel parameter may optionally be managed independently of the
rest of the module using the `::auditd::config::grub` class.

## Setup

### Setup Requirements

If `auditd::syslog` is `true`, you will need to install
[simp/rsyslog](https://forge.puppet.com/simp/rsyslog) as a dependency.

### What Auditd Affects

Only the `audit` package is installed unconditionally. Everything below happens only
when the parameter named beside it is set:

| What | Managed when |
|---|---|
| The `audit` package | always |
| The `audit` kernel parameter (applied to *all* kernels in your grub configuration) | `auditd::at_boot` is set |
| The `auditd` service | `auditd::service_ensure` or `auditd::service_enable` is set |
| Loading changes into a running `auditd` the module does not manage | `auditd::reload_on_change` is `true` |
| Individual keys in `/etc/audit/auditd.conf` | the matching parameter is set, one key each |
| Ownership and mode of `/etc/audit/auditd.conf` | `auditd::config_group` is set |
| The `auditd::plugin_dir` directory | `auditd::plugin_dir` is set |
| Rule files in `/etc/audit/rules.d` | `auditd::default_audit_profiles` is non-empty, or `auditd::rule` is used |
| The rule preamble (`00_head.rules`, `99_tail.rules`) | `auditd::default_audit_profiles` is non-empty, or `auditd::purge_auditd_rules` is `true` |
| Purging unmanaged files from `/etc/audit/rules.d` | `auditd::purge_auditd_rules` is `true` |
| `/etc/audit/audit.rules` and `.prev` ownership | one of the `auditd::audit_rules_*` parameters is set |
| `/var/log/audit` | `auditd::log_group` is set |
| The audispd `syslog` plugin (`/etc/audit/plugins.d/syslog.conf`) | `auditd::syslog` is `true` |

`/etc/audit` itself is no longer managed at all: the recursive purge that used to run
over it is gone.

### When changes take effect

Rule files and `auditd.conf` keys are written to disk as soon as Puppet runs. Whether
they reach the running system depends on who owns the service:

* **The service is managed** (`auditd::service_ensure` or `auditd::service_enable`):
  a change restarts `auditd`, which reloads `auditd.conf` and loads the rules.
* **`auditd::reload_on_change: true`**: without taking over the service, a change runs
  `auditctl --signal reload` (auditd re-reads `auditd.conf`) and `augenrules --load`
  (the kernel loads the rules). Both are skipped while `auditd` is stopped, so a daemon
  an administrator stopped stays stopped. A few `auditd.conf` keys, such as
  `tcp_listen_port`, still take effect only on a full restart; see auditd.conf(5).
* **Neither**: nothing touches the running system. The change takes effect the next
  time `auditd` starts. `systemctl restart auditd` is refused (the unit sets
  `RefuseManualStop=yes`); use `service auditd restart`, or load just the rules with
  `augenrules --load`.

If the running rule set is immutable (`-e 2`, from `auditd::immutable`), no rule change
can load until the host reboots. With `auditd::reload_on_change`, the module reads that
state from the kernel through the `auditd_state` fact and registers a `reboot_notify`
instead of a load that would change nothing.

This matters for modules that call `auditd::rule`, such as `simp/aide`, `simp/pki`,
`simp/sssd` and `simp/pupmod`. Their rules are loaded right away only when this module
manages the service or `auditd::reload_on_change` is set. The `simp:defaults` profile
manages the service.

## Usage

### Basic Usage

```puppet
# Installs the audit package. Nothing else: no rules, no service state, no
# auditd.conf edits, no kernel command line change.
include 'auditd'
```

To get the behavior releases before 11.0.0 gave you, apply the `simp:defaults`
compliance profile, or set the pieces you want yourself:

```yaml
auditd::default_audit_profiles:
  - simp
auditd::purge_auditd_rules: true
auditd::service_ensure: running
auditd::service_enable: true
auditd::at_boot: true
auditd::log_group: root
```

With `auditd::at_boot: true`, a message is printed at each Puppet run indicating that
you need to reboot for the kernel parameter to take effect, until you do.

### Disabling Auditd

`auditd::at_boot` controls only the `audit=1` kernel parameter. Setting it to `false`
actively removes that parameter from the kernel command line, which is different from
leaving it unset -- unset means this module does not touch your boot loader at all.

```yaml
# Take audit=1 off the kernel command line
auditd::at_boot: false

# Stop and disable the service
auditd::service_ensure: stopped
auditd::service_enable: false
```

### Enable/Disable sending audit event to syslog:

This capability is most useful for forwarding audit records to
remote servers as syslog messages, since these records are already
persisted locally in audit logs.  For most sites, however, using
this capability for all audit records can quickly overwhelm host
and/or network resources, especially if the messages are forwarded
to multiple remote syslog servers or persisted
locally. Site-specific, rsyslog actions to implement filtering will
likely be required to reduce this message traffic.

``auditd::syslog`` defaults to the ``simp_options::syslog`` site key, and to
``false`` when that is unset. Setting ``auditd::syslog: false`` does not
necessarily disable auditd logging to syslog -- Puppet simply stops managing the
``syslog.conf`` plugin file.

``simp_options::syslog`` also supplies the default for the deprecated
``auditd::config::audisp::syslog::rsyslog``, which hooks the dispatcher into the
SIMP rsyslog module.

The settings needed for enabling/disabling sending audit log messages to syslog
are shown below.

To enable:
```yaml
auditd::syslog: true
auditd::config::audisp::syslog::enable: true
auditd::config::audisp::syslog::drop_audit_logs: false
# The setting for drop_audit_logs enabled for backwards compatability
# but should be set to false if you want auditd to log to syslog.
```

To disable:
```yaml
auditd::syslog: true
auditd::config::audisp::syslog::enable: false
```

### Changing Key Values

To override the default values included in the module, you can either
include new values for the keys at the time that the classes are declared,
or set the values in hieradata:

```puppet

class { 'auditd':
  ignore_failures => true,
  log_group       => 'root',
  flush           => 'INCREMENTAL'
}
```

```yaml
auditd::ignore_failures: true
auditd::log_group: 'root'
auditd::flush: 'INCREMENTAL'
```

### Understanding Auditd Profiles

This module supports various configurations both independently and
simultaneously to meet varying end user requirements.

> NOTE: The default behavior of this module is to ignore any invalid rules and
> apply as much of the rule set as possible. This is done so that you end up
> with an effective level of auditing regardless of a simply typo or
> conflicting rule.  Please test your final rule sets to ensure that your
> system is auditing as expected.

The ``auditd::default_audit_profiles`` parameter determines which profiles are
included, and in what order the rules are added to the system.

The ``auditd::default_audit_profiles`` has a default setting of ``[ 'simp' ]``
which applies the optimized SIMP auditing profile which is suitable for meeting
most generally available compliance requirements. It does not, however,
generally appease the scanning utilities since it optimizes the rules for
performance and most scanners cannot handle audit rule optimizations.

There are three other profiles available in the system by default:

* ``stig``     => Applies the rules as defined in the latest covered DISA STIG
* ``custom``   => Allows users to define their own rules easily via Hiera
* ``built_in`` => Allows usage of EL8+ included sample rulesets to configure system

There are a large number of parameters exposed for each profile that are meant
to be set via Hiera and you should take a look at the REFERENCE.md file to
understand the full capabilities of each profile.

#### Stacking Profiles

In some cases, you may want to combine profiles in different orders. This may
either be done in order to pass a particular scanning engine or to ensure that
items that are not caught by the first profile are caught by the second.

Profiles are included and ordered by passing an Array to the
``auditd::default_audit_profiles`` parameter and are added to auditd in the
order in which they are defined in the Array.

For example, this (the default) would only add the ``simp`` profile:

```yaml
auditd::default_audit_profiles:
  - 'simp'
```

Likewise, this would add the ``stig`` rules prior to the ``simp`` profile:

```yaml
auditd::default_audit_profiles:
  - 'stig'
  - 'simp'
```

#### The Custom Profile

Users may wish to either completely override the default profiles or
prepend/append their own rules to the stack for compliance purposes.

You can easily do this via Hiera as shown in the following example:

```yaml
auditd::config::audit_profiles::custom::rules:
  - '-w /etc/passwd -wa -k passwd_files'
  - '-w /etc/shadow -wa -k passwd_files'
```

To activate the custom profile, you will need to set the
``auditd::default_audit_profiles`` parameter as shown in the following
examples:

##### Override All Other Profiles

```yaml
auditd::default_audit_profiles:
  - 'custom'
```

##### Prepend Before the SIMP Profile

```yaml
auditd::default_audit_profiles:
  - 'custom'
  - 'simp'
```

##### Append After the SIMP and STIG Profiles

```yaml
auditd::default_audit_profiles:
  - 'simp'
  - 'stig'
  - 'custom'
```

#### The Built-in Profile

Starting with release 3.0.0-17 on EL8 hosts, the audit package includes a number
of ``sample-rules`` under ``/usr/share/audit/sample-rules`` that can be used
to configure a system fairly completely. Within these rules are sets for STIG,
OSPP, etc. that can simply be moved to ``/etc/audit/rules.d`` and compiled with
``augenrules`` to configure a system.

##### Disabling All SIMP-provided Profiles

Most likely, if using the sample rulesets from the built-in profile, you will
want to disable included SIMP profiles (not necessary, but may include
overlapping rules if not). To do this:

```yaml
auditd::default_audit_profiles:
  - 'built_in'
```

##### Enabling Sample Rulesets with Built-in Profile

To enable specific sample rulesets, simply include them in the built-in profile
parameter:

```yaml
auditd::config::audit_profiles::built_in::rulesets:
  - 'base-config'
  - 'stig'
  - 'finalize'
```

where the ruleset names are found via the custom fact ``auditd_sample_rulesets``

##### Configuring Complete Rulesets with Built-in Profile

If you are only planning to use the ``built_in`` profile and the included sample
rulesets to configure the system, it will be worth noting that profile-specific
sample files include configuration information within comments in the files as well.

As an example, the STIG rules sample file will note that it relies on ``base-config``
and ``finalize`` rulesets to be feature-complete. Other rulesets will contain similar
information.

### Adding One-Off Rules

Rules are alphanumerically ordered based on file-system globbing. It is
recommended that users use the ``auditd::rule`` defined type for adding rules.

Other options are available with ``auditd::rule`` but these are the most
commonly used.

On its own, ``auditd::rule`` writes only the rule file. The preamble that
``augenrules`` loads ahead of the rules comes from the ``audit`` package's own
``rules.d/audit.rules`` until this module is asked to manage the directory, with
a profile or ``auditd::purge_auditd_rules: true``. Only then are
``auditd::buffer_size``, ``auditd::failure_mode``, ``auditd::rate``,
``auditd::ignore_errors``, ``auditd::ignore_failures``,
``auditd::backlog_wait_time``, ``auditd::loginuid_immutable`` and
``auditd::immutable`` managed. Unless the purge is on, the packaged
``rules.d/audit.rules`` stays and its ``-b`` and ``-f`` win over
``00_head.rules``; see the breaking changes above.

#### Adding Regular Filter Rules

```puppet

auditd::rule { 'failed_file_creation':
  content => '-a always,exit -F arch=b64 -S creat -F exit=-EACCES -k failed_file_creation'
}
```

```puppet

auditd::rule { 'passwd_file_watches':
  content => [
    '-w /etc/passwd -wa -k passwd_files',
    '-w /etc/shadow -wa -k passwd_files'
  ]
}
```

#### Prepend and Drop Everything From a User

This will make your rule land in the ``00`` set of rules.

```puppet

auditd::rule { 'pre_drop_user_5000':
  content => '-a exit,never -F auid=5000',
  prepend => true
}
```

## Development

Please read our [Contribution Guide](https://simp.readthedocs.io/en/stable/contributors_guide/Contribution_Procedure.html)

### Acceptance tests

This module includes [Beaker](https://github.com/puppetlabs/beaker) acceptance
tests using the SIMP [Beaker Helpers](https://github.com/simp/rubygem-simp-beaker-helpers).
By default the tests use [Vagrant](https://www.vagrantup.com/) with
[VirtualBox](https://www.virtualbox.org) as a back-end; Vagrant and VirtualBox
must both be installed to run these tests without modification. To execute the
tests run the following:

```shell
bundle exec rake beaker:suites
```

Some environment variables may be useful:

```shell
BEAKER_debug=true
BEAKER_provision=no
BEAKER_destroy=no
BEAKER_use_fixtures_dir_for_modules=yes
BEAKER_fips=yes
```

* `BEAKER_debug`: show the commands being run on the STU and their output.
* `BEAKER_destroy=no`: prevent the machine destruction after the tests finish so you can inspect the state.
* `BEAKER_provision=no`: prevent the machine from being recreated. This can save a lot of time while you're writing the tests.
* `BEAKER_use_fixtures_dir_for_modules=yes`: cause all module dependencies to be loaded from the `spec/fixtures/modules` directory, based on the contents of `.fixtures.yml`.  The contents of this directory are usually populated by `bundle exec rake spec_prep`.  This can be used to run acceptance tests to run on isolated networks.
* `BEAKER_fips=yes`: enable FIPS-mode on the virtual instances. This can
  take a very long time, because it must enable FIPS in the kernel
  command-line, rebuild the initramfs, then reboot.

Please refer to the [SIMP Beaker Helpers documentation](https://github.com/simp/rubygem-simp-beaker-helpers/blob/master/README.md)
for more information.
