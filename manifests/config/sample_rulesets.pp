# NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# @summary This class is called from auditd for service config.
#
# @author https://github.com/simp/pupmod-simp-auditd/graphs/contributors
#
class auditd::config::sample_rulesets {
  $_sample_rules_basedir = '/usr/share/audit/sample-rules'
  # At this point we should not have an empty rulesets list...so we need to
  # validate the list; we should be OK skipping nonexistent ones those, but
  # SHOULD notify of this
  $auditd::sample_rulesets.each |$_ruleset| {
    if $_ruleset in keys($facts['auditd_sample_rulesets']) {
      $_order = $facts['auditd_sample_rulesets'][$_ruleset]['order']

      # Copy the ruleset into place via puppet file resource and notify service
      if $_ruleset == 'privileged' {
        # We need to process the script within the privileged rules comments
        # A little hacky, but we will use the sha512sum of the original rules sample
        # file to evaluate easily if it needs to be regenerated
        exec { 'generate_privileged_script':
          command => "sha512sum ${_sample_rules_basedir}/${_order}-${_ruleset}.rules > ${_sample_rules_basedir}/.${_order}-${_ruleset}.rules.sha512 && sed -e 's|^#||' -e 's|>[[:space:]][[:alnum:]]*.rules|> ${_sample_rules_basedir}/${_order}-${_ruleset}.rules.evaluated|' ${_sample_rules_basedir}/${_order}-${_ruleset}.rules > /usr/local/sbin/generate_privileged_audit_sample_rules.sh",
          path    => ['/usr/bin', '/usr/sbin', '/bin', '/sbin'],
          unless  => [
            "test -f ${_sample_rules_basedir}/.${_order}-${_ruleset}.rules.sha512",
            "sha512sum -c --status ${_sample_rules_basedir}/.${_order}-${_ruleset}.rules.sha512"
          ],
          notify  => Exec['build_privileged_ruleset'],
        }

        exec { 'build_privileged_ruleset':
          command     => '/bin/bash "/usr/local/sbin/generate_privileged_audit_sample_rules.sh"',
          refreshonly => true,
        }

        # If we got to here, we should be able to evaluate that the generated ruleset is different
        # and drop into place only if we need to
        file { "/etc/audit/rules.d/${_order}-${_ruleset}.rules":
          ensure  => 'file',
          source  => "file://${_sample_rules_basedir}/${_order}-${_ruleset}.rules.evaluated",
          notify  => Class['auditd::service'],
          require => Exec['build_privileged_ruleset'],
        }
      } else {
        file { "/etc/audit/rules.d/${_order}-${_ruleset}.rules":
          ensure => 'file',
          source => "file://${_sample_rules_basedir}/${_order}-${_ruleset}.rules",
          notify => Class['auditd::service'],
        }
      }
    } else {
      notify { "${_ruleset} not found":
        message => "Sample auditd ruleset: ${_ruleset} is not found in system sample rulesets...skipping...",
      }
    }
  }
}
