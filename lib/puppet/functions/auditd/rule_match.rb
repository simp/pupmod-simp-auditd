# @summary Returns the `file_line` match for one rule in a profile's base rules file
#
# The match is the rule up to its key, with regex metacharacters escaped, so a
# changed tag replaces the rule in place instead of adding a second copy. It
# accepts either key form, `-k` or `-F key=`.
#
# Any `auid>=` value is matched too, so a changed `uid_min` also replaces the
# rule in place.
#
# A rule that more than one toggle writes, each with its own key, is matched
# with its key as well. Otherwise each toggle's line would replace the other's
# on every run.
Puppet::Functions.create_function(:'auditd::rule_match') do
  # @param rule The rule without its key, e.g. `-w /etc/passwd -p wa`
  # @param any_syscalls Also match any `-S` list, so a changed list replaces
  #   the rule in place
  # @param key Match only the rule with this key
  # @return [String] An anchored regex, as a String
  #
  dispatch :rule_match do
    param 'String[1]', :rule
    optional_param 'Boolean', :any_syscalls
    optional_param 'Optional[String[1]]', :key
    return_type 'String[1]'
  end

  def rule_match(rule, any_syscalls = false, key = nil)
    pattern = escape_regex(rule)
    pattern = pattern.gsub(%r{auid>=\d+}) { 'auid>=\d+' }
    pattern = pattern.sub(%r{ -S \S+}) { ' -S \S+' } if any_syscalls

    key ? "^#{pattern} (?:-k |-F key=)#{escape_regex(key)}$" : "^#{pattern} (?:-k |-F key=)"
  end

  def escape_regex(string)
    string.gsub(%r{[.*+?^$|()\[\]{}\\]}) { |c| "\\#{c}" }
  end
end
