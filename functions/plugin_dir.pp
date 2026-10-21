# @summary The auditd plugin directory
#
# Without an argument, the directory the package ships and auditd compiles in:
# `/etc/audit/plugins.d`, or `/etc/audisp/plugins.d` on auditd 2.
#
# With one, that path normalized the way Puppet normalizes a File's path:
# repeated slashes collapsed and a trailing slash stripped. Two spellings of
# one directory would otherwise be two File titles for the same path.
#
# @param plugin_dir
#   A plugin directory a site set, such as `auditd::plugin_dir`.
#
# @return [Stdlib::Absolutepath]
#
function auditd::plugin_dir(
  Optional[Stdlib::Absolutepath] $plugin_dir = undef,
) >> Stdlib::Absolutepath {
  if $plugin_dir {
    $plugin_dir.regsubst('/+', '/', 'G').regsubst('(.)/$', '\1')
  }
  elsif auditd::auditd2() {
    '/etc/audisp/plugins.d'
  }
  else {
    '/etc/audit/plugins.d'
  }
}
