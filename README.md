[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/73/badge)](https://bestpractices.coreinfrastructure.org/projects/73)
[![Puppet Forge](https://img.shields.io/puppetforge/v/simp/auditd.svg)](https://forge.puppetlabs.com/simp/auditd)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/simp/auditd.svg)](https://forge.puppetlabs.com/simp/auditd)
[![Build Status](https://travis-ci.org/simp/pupmod-simp-auditd.svg)](https://travis-ci.org/simp/pupmod-simp-auditd)

#### Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Setup - The basics of getting started with auditd](#setup)
    * [What auditd affects](#what-auditd-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with auditd](#beginning-with-auditd)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)
      * [Acceptance Tests - Beaker env variables](#acceptance-tests)

## Overview

This module manages the Audit daemon, kernel parameters, and related subsystems.

## This is a SIMP module
This module is a component of the [System Integrity Management
Platform](https://github.com/NationalSecurityAgency/SIMP), a compliance
management framework built on Puppet.

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
sets.

By default, a rule set is provided that should meet a reasonable set of
operational goals for most environments.

The `audit` kernel parameter may optionally be managed independently of the
rest of the module using the `::auditd::config::grub` class.

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

To disable auditd at boot, set the following in hieradata:

```yaml
auditd::at_boot : false
```

#### Changing Key Values

To override the default values included in the module, you can either
include new values for the keys at the time that the classes are declared,
or set the values in hieradata:

```puppet

class { '::auditd':
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

# Limitations

SIMP Puppet modules are generally intended to be used on a Redhat Enterprise Linux-compatible distribution such as EL6 and EL7.

## Development

Please read our [Contribution Guide](https://simp.readthedocs.io/en/master/contributors_guide/Contribution_Procedure.html)

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
