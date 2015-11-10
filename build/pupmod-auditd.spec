Summary: Auditd Puppet Module
Name: pupmod-auditd
Version: 5.0.0
Release: 1
License: Apache License, Version 2.0
Group: Applications/System
Source: %{name}-%{version}-%{release}.tar.gz
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Requires: pupmod-augeasproviders_grub
Requires: pupmod-common >= 4.2.0-7
Requires: pupmod-simplib >= 1.0.0-0
Requires: pupmod-rsyslog >= 4.1.0-10
Requires: pupmod-simpcat >= 2.0.0-0
Requires: puppet >= 3.3.0
Buildarch: noarch
Requires: simp-bootstrap >= 4.2.0
Obsoletes: pupmod-auditd-test

Prefix: /etc/puppet/environments/simp/modules

%description
This Puppet module provides the capability to configure auditd and rules
affecting your system.

%prep
%setup -q

%build

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/auditd

dirs='files lib manifests templates'
for dir in $dirs; do
  test -d $dir && cp -r $dir %{buildroot}/%{prefix}/auditd
done

mkdir -p %{buildroot}/usr/share/simp/tests/modules/auditd

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/auditd

%files
%defattr(0640,root,puppet,0750)
%{prefix}/auditd

%post
#!/bin/sh

if [ -d %{prefix}/auditd/plugins ]; then
  /bin/mv %{prefix}/auditd/plugins %{prefix}/auditd/plugins.bak
fi

%postun
# Post uninstall stuff

%changelog
* Mon Nov 09 2015 Chris Tessmer <chris.tessmer@onypoint.com> - 5.0.0-1
- migration to simplib and simpcat (lib/ only)

* Tue Oct 20 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 5.0.0-0
- Module refactor to the new SIMP standard
- Fixes for the audit dispatcher and syslog connections

* Mon Sep 07 2015 Chris Tessmer <chris.tessmer@onyxpoint.com> - 4.1.0-13
- Updated facts from $::lsbmajdistrelease to $::operatingsystemmajrelease.

* Tue Jul 21 2015 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-12
- Updated to use the new rsyslog module.

* Thu Feb 19 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-11
- Migrated to the new 'simp' environment.

* Fri Jan 16 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-10
- Changed puppet-server requirement to puppet

* Wed Nov 19 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-9
- Updated auditd::to_syslog to support multiple log servers and
  support for native TLS.

* Sat Sep 06 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-8
- Fixed a missing rule for RHEL<7 that did not properly drop all of
  the useless audit data.

* Sat Aug 23 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-7
- Updated to use the new reboot_notify native type.

* Sun Jul 13 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-6
- Updated to support both grub and grub2
- Fixed a bug in the audit ruleset where the initial drop rule was set to drop
  everything that was *not* anonymous.
- Added support for /etc/audit/rules.d for RHEL7 systems.

* Sun Jun 22 2014 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-5
- Removed MD5 file checksums for FIPS compliance.

* Fri Jun 20 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-5
- Pointed concat fragment auditd+head at the correct template!
- Updated to support RHEL7

* Wed May 21 2014 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-4
- Added the ability to put rules before the default rule body in audit.rules.
- Added validation to add_rules.pp.

* Fri Mar 28 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-3
- The template for auditing the rotated audit logs had a one-off error
  preventing the audit of the last rotated log.
- Spec tests were added.

* Fri Mar 14 2014 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-2
- Added class for auditing grub.

* Thu Feb 13 2014 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-1
- Converted all string booleans to native booleans.

* Mon Nov 04 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-0
- Added support for audispd based on patches provided by Raymond Page
  <raymond.page@icat.us>.
- Removed the old rsyslog file tap on audit.log.
- Folded the auditd::conf define into the auditd main class since
  parameterized classes eliminate the need for the define.
    * Breaking Change

* Mon Oct 28 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-11
- Updated the audit base rules to compress and reorder many of the rules to
  allow for greater processing efficiency.
- Added checks for kernel module manipulation in accordance with
  CCE-26610-6.
- Mapped all audit rules to their associated SSG rules in the file
  template.

* Thu Oct 03 2013 Nick Markowski <nmarkowski@keywcorp.com> - 4.0.0-11
- Updated templates to reference instance variables with @

* Wed Jul 17 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-10
- Removed the sgid binary check in the audit rules because it doesn't
  actually make any sense.

* Thu Jun 27 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-9
- Added audit rules to catch the execution of sgid and suid binaries.
- Added the ability to rate limit the auditd messages. If you use this, you
  probably want to change the failure mode to 1.
- Added the ability to ignore failures in the audit configuration and continue
  and set it to true by default. Since the rules are automatically managed, the
  likelihood of one being wrong is fairly high. Also, rules will fail if a file
  doesn't exist which isn't all that helpful.
- Removed the watch on /proc/kcore since it wasn't really helpful and was
  throwing SELinux AVC's on startup.
- Added default auditing to /etc/yum.conf and /etc/yum.repos.d

* Tue Apr 09 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-8
- Skip any rule that does not load properly so that we have as much of the
  configuration active as possible.

* Thu Dec 13 2012 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-7
- Updated to require pupmod-common >= 2.1.1-2 so that upgrading an old
  system works properly.

* Fri Nov 30 2012 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-6
- Added a cucumber test to ensure that the auditd daemon starts when including
  audit in the puppet server manifest.

* Tue Sep 18 2012 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-5
- Updated all references of /etc/modprobe.conf to /etc/modprobe.d/00_simp_blacklist.conf
  as modprobe.conf is now deprecated.

* Thu Jun 07 2012 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-4
- Ensure that Arrays in templates are flattened.
- Call facts as instance variables.
- Moved mit-tests to /usr/share/simp...
- Moved rsyslog module inclusion from init.pp to to_syslog.pp where it is used.
- Updated pp files to better meet Puppet's recommended style guide.

* Fri Mar 02 2012 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-3
- Improved test stubs.

* Mon Jan 30 2012 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-2
- Removed all references to 'entry' rules since they are deprecated.
- Removed the watch rule for /etc/firmware since it was removed in RHEL6 and
  pretty much useless anyway.
- Added test stubs

* Mon Dec 26 2011 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-1
- Scoped all of the top level variables.

* Fri Oct 28 2011 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-0
- Removed the base audit of /etc/ldap.conf since it was redundant.

* Mon Oct 10 2011 Trevor Vaughan <tvaughan@onyxpoint.com> - 2.0.0-3
- Updated to put quotes around everything that need it in a comparison
  statement so that puppet > 2.5 doesn't explode with an undef error.

* Thu Mar 17 2011 Trevor Vaughan <tvaughan@onyxpoint.com> - 2.0.0-2
- Modified several audit rules to be a bit more complete and to conform to some
  of the Red Hat syntax standards.

* Fri Feb 11 2011 Trevor Vaughan <tvaughan@onyxpoint.com> - 2.0.0-1
- Updated to use concat_build and concat_fragment types.

* Tue Jan 11 2011 Trevor Vaughan <tvaughan@onyxpoint.com> - 2.0.0-0
- Refactored for SIMP-2.0.0-alpha release

* Tue Oct 26 2010 Trevor Vaughan <tvaughan@onyxpoint.com> - 1-2
- Converting all spec files to check for directories prior to copy.

* Wed Jul 28 2010 Trevor Vaughan <tvaughan@onyxpoint.com> - 1.0-1
- More code refactoring
- Made log_file configurable in to_syslog define.

* Wed May 19 2010 Trevor Vaughan <tvaughan@onyxpoint.com> - 1.0-0
- Code + doc refactor

* Wed May 12 2010 Trevor Vaughan <tvaughan@onyxpoint.com> - 0.1-12
- Added the option $root_audit_level to auditd::conf
  - The allowed strings are basic(default), aggressive, insane
    - Basic(default): Safe, should not follow program execution outside of the base app
    - Aggressive: Adds execve
    - Insane: Adds fork, vfork, write, chown, creat, link, mkdir, rmdir

* Fri Feb 19 2010 Trevor Vaughan <tvaughan@onyxpoint.com> - 0.1-11
- Removed watch on /etc. That was a very bad rule.

* Tue Dec 15 2009 Trevor Vaughan <tvaughan@onyxpoint.com> - 0.1-10
- Audit rules now properly handle 64 and 32 bit architectures (for now).
  Previously, the 64 bit calls were not handled properly.

