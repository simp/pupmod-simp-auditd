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

`auditd::config::grub` is included only when `$at_boot` is set, and `auditd::service`
declares `Service['auditd']` only when `$service_ensure` or `$service_enable` is set.
Both are unset by default.

### Nothing is managed unless it is asked for

As of 11.0.0 this is the rule the whole module is built around: a bare `include auditd`
declares `Package[audit]` and nothing else. Every other resource -- the service, the
GRUB entry, the rule files, the `rules.d` purge, `auditd.conf` keys, `/var/log/audit`,
`/etc/audit/auditd.conf` -- appears only because a parameter asked for it, and every
one of those parameters defaults to `undef`, `false` or `[]`.

Before adding a resource, find the parameter that gates it. If there isn't one, that is
the change to make first. `spec/classes/init_spec.rb` and `spec/classes/config_spec.rb`
both compare the entire default catalogue against `Package[audit]`, so an ungated
resource fails the suite rather than slipping through.

The SIMP-shipped values that used to be module defaults now live in the `simp:defaults`
compliance profile, which sites apply deliberately.

### Audit Profile System

The `$default_audit_profiles` parameter (Array of `AuditProfile`) controls which rule sets are applied. Profiles are stackable — multiple can be active simultaneously:

- `simp` — SIMP default profile (most commonly used)
- `stig` — DISA STIG compliance rules
- `custom` — User-supplied rules from `auditd::rule` defined type
- `built_in` — EL8+ native sample rulesets from the OS

Custom rules are injected using the `auditd::rule` defined type (`manifests/rule.pp`), which creates files in `/etc/audit/rules.d/`.

The `simp` and `stig` base rules files are not rendered from a template. Each profile
lists its toggles in `$_all_toggles`, and `auditd::config::profile_rules` writes each
rule with `file_line`, matched by `auditd::rule_match` on the body before its key. A
body two toggles share is matched with its key as well, or the two would rewrite each
other's line on every run. The toggles default to `undef` (leave the rule alone);
`simp:defaults` sets them. `spec/support/file_lines.rb` replays a catalogue's
`File_line`s against a file, which is how the specs check fresh output, upgrades from
the old rendered files, and convergence.

### Auditd Version Handling

Two custom facts in `lib/facter/auditd_version.rb` drive version-dependent behavior:

- `auditd_version` — full version string, gates code paths via `versioncmp`
  (`init.pp`, `config/logging.pp`, `config/audisp.pp`, `config/audisp/syslog.pp`)
- `auditd_major_version` — major number only. It used to select a
  `data/auditd/version-N.yaml` Hiera layer; that layer is gone, so the fact now only
  matters to specs and to anything that reads it directly

Both derive from the `simplib__auditd` structured fact, which does not resolve until
auditing is enabled in the kernel, and on EL10 until `audit-rules` provides `auditctl`,
so either can be `undef`. `init.pp` tests the fact before using it. `config/logging.pp`
and `config/audisp/syslog.pp` treat a missing fact as 3.0 with `pick()`, so the syslog
plugin is configured on the first run. `config/audisp.pp` calls `versioncmp` unguarded;
that is safe only because `config/logging.pp` declares it only when the fact is present
and below 3.0. Keep that guard in mind before declaring it elsewhere.

### auditd.conf

Managed key-by-key with `ini_setting` (puppetlabs-inifile) in `manifests/config.pp`,
rather than by rendering the whole file. The package's own `auditd.conf` stays in
place and only the keys this module has an opinion about are edited — keys the module
does not manage keep their vendor values. To manage a new key, add it to one of the
`$_auditd_conf_*` hashes in `config.pp`.

### Hiera Data Structure

`hiera.yaml` has a single layer, `data/common.yaml`, which holds `lookup_options` and
little else. The per-auditd-version (`auditd/version-N.yaml`) and per-OS
(`os/<distro>-<major>.yaml`) layers were removed in 11.0.0: every supported platform
carried identical values, so they were defaults wearing a `confine` rather than
platform knowledge. Do not reintroduce a layer to express a default -- put it in the
parameter, or in the `simp:defaults` profile if it is a SIMP opinion rather than a
module one.

Many array parameters (e.g., syscall lists, ignore lists) use `lookup_options: merge: unique` to allow Hiera to combine values from multiple layers rather than replacing them.

### Key Parameters in `auditd` (init.pp)

| Parameter | Purpose |
|---|---|
| `$enable` | **Deprecated.** `undef` does nothing; `true` warns; `false` warns and implies a stopped, disabled service and `at_boot => false` where those are unset. It no longer stands the module down |
| `$service_ensure` / `$service_enable` | Declare `Service['auditd']` at all; unset by default |
| `$purge_auditd_rules` | Whether `/etc/audit/rules.d` is purged of unmanaged files |
| `$log_group` | Group owning `/var/log/audit`; also written as the `log_group` key in `auditd.conf` |
| `$config_group` | Group owning the audit *configuration*. Deliberately independent of `$log_group` |
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

**Optional**: `simp/rsyslog` — pulled in only when audisp→syslog forwarding is enabled (`manifests/config/audisp/syslog.pp` calls `simplib::assert_optional_dependency` for `'simp/rsyslog'`). Not declared in `metadata.json` dependencies.

## Supported Platforms

RHEL-family: RedHat/AlmaLinux/Rocky/OracleLinux 8, 9, and 10, plus CentOS 9 and 10. OpenVox 8.x.
