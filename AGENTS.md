# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Overview

This is a Puppet module (`pupmod-simp-auditd`) for managing the Linux audit daemon (auditd) and related subsystems. It is part of the [SIMP](https://simp-project.com/) compliance framework but can also be used standalone.

## Development Commands

All commands run via Bundler. Install dependencies first:

```bash
bundle install
```

### Linting and Syntax Checks

```bash
bundle exec rake syntax          # Puppet syntax checking
bundle exec rake lint            # Puppet-lint style checks
bundle exec rake metadata_lint   # Validate metadata.json
bundle exec rake rubocop         # Ruby style checking (non-blocking in CI)
```

### Unit Tests

```bash
bundle exec rake spec            # Run all unit tests
bundle exec rake spec_prep       # Prepare fixture modules without running tests
```

Run a single spec file:

```bash
bundle exec rspec spec/classes/init_spec.rb
bundle exec rspec spec/classes/config/grub_spec.rb
```

### Acceptance Tests (Beaker + libvirt)

```bash
bundle exec rake beaker:suites[default,almalinux9]
bundle exec rake beaker:suites[default,almalinux10]
```

## Architecture

### Class Hierarchy

The main entry point is `auditd` (`manifests/init.pp`). When `$enable` is true it includes three private classes:

```
auditd
├── auditd::install          # Package installation
├── auditd::config           # Configuration orchestration
│   ├── auditd::config::audit_profiles
│   │   └── auditd::config::audit_profiles::{simp,stig,custom,built_in}
│   ├── auditd::config::audisp
│   │   └── auditd::config::audisp::syslog
│   └── auditd::config::logging
└── auditd::service          # auditd systemd service
```

`auditd::config::grub` is always included (even when `$enable` is false) because kernel audit parameters are managed independently of the service.

### Audit Profile System

The `$default_audit_profiles` parameter (Array of `AuditProfile`) controls which rule sets are applied. Profiles are stackable — multiple can be active simultaneously:

- `simp` — SIMP default profile (most commonly used)
- `stig` — DISA STIG compliance rules
- `custom` — User-supplied rules from `auditd::rule` defined type
- `built_in` — EL8+ native sample rulesets from the OS

Custom rules are injected using the `auditd::rule` defined type (`manifests/rule.pp`), which creates files in `/etc/audit/rules.d/`.

### Auditd Version Handling

The module supports auditd v2 and v3, which have different `auditd.conf` configuration keys. The `auditd_version` and `auditd_major_version` custom facts (in `lib/facter/`) drive version-specific template selection. Templates are split across:

- `templates/etc/audit/auditd.conf.epp` — common settings
- `templates/etc/audit/auditd.2.conf.epp` — v2-only keys
- `templates/etc/audit/auditd.3.conf.epp` — v3-only keys

### Hiera Data Structure

Module defaults live in `data/`:
- `common.yaml` — module-wide defaults and deep merge lookup options
- `auditd/version-2.yaml` / `auditd/version-3.yaml` — auditd-version-specific defaults
- `os/<distro>-<major>.yaml` — OS-specific overrides (mainly `plugin_dir` paths)

Many array parameters (e.g., syscall lists, ignore lists) use `lookup_options: merge: unique` to allow Hiera to combine values from multiple layers rather than replacing them.

### Key Parameters in `auditd` (init.pp)

| Parameter | Purpose |
|---|---|
| `$enable` | Master switch — when false, service is stopped and rules are cleared |
| `$default_audit_profiles` | Which rule profiles to apply |
| `$at_boot` | Whether `audit=1` is set on the kernel command line (via Grub) |
| `$immutable` | Lock audit config (requires reboot to change) |
| `$root_audit_level` | Syscall audit intensity for root: `basic`, `aggressive`, `insane` |
| `$uid_min` | Minimum UID for human users (used to filter system service events) |
| `$ignore_anonymous` | Drop events with `auid=-1` |

### Testing Conventions

- Spec tests use `simp-rspec-puppet-facts` to iterate over multiple OS/Puppet version combinations automatically.
- `spec/spec_helper.rb` configures the Hiera fixture path and enables SIMP fact sets.
- Acceptance tests target AlmaLinux 9 and 10 with libvirt/Vagrant; they require `BEAKER_*` environment variables for VM configuration.
- The `.fixtures.yml` pins all dependency modules for reproducible test runs.

## Module Dependencies

**Required**: `puppetlabs/stdlib`, `simp/simplib`, `puppet/augeasproviders_grub`

**Optional**: `simp/rsyslog` (syslog forwarding), `simp/pki`, `simp/compliance_markup`

## Supported Platforms

RHEL-family OS versions 8, 9, and 10 (CentOS, RedHat, AlmaLinux, Rocky, OracleLinux, Amazon Linux 2). Puppet 7.x and 8.x.
