# NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# @summary Declares the auditd plugin directories
#
# A relocated `auditd::plugin_dir`, and under
# `auditd::manage_plugins_d_attributes` the package's plugin directory,
# recursively.
#
# Recursion reaches plugin configs other packages install (such as
# setroubleshoot-server's sedispatch.conf). Without a purge it only changes
# their owner/group/mode, but those are files this module doesn't own, so it
# takes a parameter of its own.
#
# This class is included by auditd::config rather than contained, so a repair
# here does not refresh auditd::service: auditd reads its plugin configs as
# root and needs no restart for an ownership or mode change, and a restart
# leaves a gap in audit collection. syslog.conf, which this module writes,
# keeps its own resource (see $auditd::config::plugin_file_attributes), which
# takes precedence over the recursion.
#
# The recursion does not follow symlinks (links => manage), so it never
# changes a file outside these directories, and a plugin directory that is
# itself a symlink is left alone; point plugin_dir at the real directory
# instead.
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::plugins_d {
  assert_private()

  $auditd::config::_plugin_dirs.each |$dir, $ensure| {
    file { $dir:
      ensure  => $ensure,
      owner   => 'root',
      # A relocated plugin_dir has had the group since 11.0.0, so the
      # directories always get it; only syslog.conf's is opt-in.
      group   => $auditd::config::_config_group,
      mode    => $auditd::config::_plugin_file_mode,
      recurse => $auditd::manage_plugins_d_attributes,
      require => Package[$auditd::package_name],
    }
  }

  # Recursion only sees files that exist when a directory's File is
  # evaluated, so plugin packages go in first, or their configs wait a second
  # run for their attributes. auditd::config::audisp::syslog tags the
  # audispd-plugins package it installs; a site installing another plugin
  # package in the same run, such as setroubleshoot-server, can tag it
  # 'auditd_plugin' too. The collector also realizes a virtual package with
  # that tag.
  unless empty($auditd::config::_plugin_dirs) {
    Package <| tag == 'auditd_plugin' |> -> File[keys($auditd::config::_plugin_dirs)]
  }
}
