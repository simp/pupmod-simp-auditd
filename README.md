[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-dummy.svg)](https://travis-ci.org/simp/pupmod-simp-dummy) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)

#### Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Setup - The basics of getting started with dummy](#setup)
    * [What dummy affects](#what-dummy-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with dummy](#beginning-with-dummy)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)
      * [Acceptance Tests - Beaker env variables](#acceptance-tests)

## Overview

**FIXME:** The text below is boilerplate copy.  Ensure that it is correct and remove this message!

A one-maybe-two sentence summary of what the module does/what problem it solves. This is your 30 second elevator pitch for your module. Consider including OS/Puppet version it works with.

## This is a SIMP module
This module is a component of the [System Integrity Management Platform](https://github.com/NationalSecurityAgency/SIMP), a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP) and visit our [developer wiki](https://simp-project.atlassian.net/wiki/display/SD/SIMP+Development+Home).

_**FIXME: verify that the following paragraph fits this module's characteristics!**_

This module is optimally designed for use within a larger SIMP ecosystem, but it can be used independently:
* When included within the SIMP ecosystem, security compliance settings will be managed from the Puppet server.
* If used independently, all SIMP-managed security subsystems are disabled by default and must be explicitly opted into by administrators.  Please review the `client_nets` and `$enable_*` parameters in `manifests/init.pp` for details.


## Module Description

**FIXME:** The text below is boilerplate copy.  Ensure that it is correct and remove this message!

If applicable, this section should have a brief description of the technology the module integrates with and what that integration enables. This section should answer the questions: "What does this module *do*?" and "Why would I use it?"

If your module has a range of functionality (installation, configuration, management, etc.) this is the time to mention it.

## Setup

### What dummy affects

**FIXME:** The text below is boilerplate copy.  Ensure that it is correct and remove this message!

* A list of files, packages, services, or operations that the module will alter, impact, or execute on the system it's installed on.
* This is a great place to stick any warnings.
* Can be in list or paragraph form.

### Setup Requirements **OPTIONAL**

**FIXME:** The text below is boilerplate copy.  Ensure that it is correct and remove this message!

If your module requires anything extra before setting up (pluginsync enabled, etc.), mention it here.

### Beginning with dummy

The very basic steps needed for a user to get the module up and running.

If your most recent release breaks compatibility or requires particular steps for upgrading, you may wish to include an additional section here: Upgrading (For an example, see http://forge.puppetlabs.com/puppetlabs/firewall).

## Usage

**FIXME:** The text below is boilerplate copy.  Ensure that it is correct and remove this message!

Put the classes, types, and resources for customizing, configuring, and doing the fancy stuff with your module here.

## Reference

**FIXME:** The text below is boilerplate copy.  Ensure that it is correct and remove this message!

Here, list the classes, types, providers, facts, etc contained in your module. This section should include all of the under-the-hood workings of your module so people know what the module is touching on their system but don't need to mess with things. (We are working on automating this message!)

## Limitations

**FIXME:** The text below is boilerplate copy.  Ensure that it is correct and remove this message!

SIMP Puppet modules are generally intended to be used on a Redhat Enterprise Linux-compatible distribution such as EL6 and EL7.

## Development

Please see the [SIMP Contribution Guidelines](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP).


### Acceptance tests

To run the system tests, you need [Vagrant](https://www.vagrantup.com/) installed. Then, run:

```shell
bundle exec rake acceptance
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
