require 'spec_helper_acceptance'

# Retrieve a subset of test results based on a match to
# rule_search_string
#
# FIXME:
# - This is a hack! Should be searching for rules based on a set
#   set of STIG ids, but don't see those ids in the oscap results xml.
#   Further mapping is required...
# - Create the same report structure as inspec
def get_oscap_test_results(rule_search_string)
  require 'nokogiri'

  results_xml = Dir.glob('sec_results/ssg/el*-ssg-*.xml').sort!
  results_xml.sort!
  fail('Could not find results XML file in sec_results/ssg') if results_xml.empty?

  puts "Processing #{results_xml.last}"
  doc = Nokogiri::XML(File.open(results_xml.last))

  # because I'm lazy
  doc.remove_namespaces!

  # XPATH to get the pertinent test results:
  #   Any node named 'rule-result' for which the attribute 'idref'
  #   contains rule_search_string
  result_nodes = doc.xpath("//rule-result[contains(@idref,'#{rule_search_string}')]")

  failed_tests = []
  passed_tests = []
  result_nodes.each do |rule_result|
    # Results are recorded in a child node named 'result'.
    # Within the 'result' node, the actual result string is
    # the content of that node's (only) child node.
    result = rule_result.element_children.at('result')
    if result.child.content == 'fail'
      failed_tests << rule_result
    elsif result.child.content == 'pass'
      passed_tests << rule_result
    else
      # 'notselected', so do nothing
    end
  end
  { :rule_search_string => rule_search_string,
    :passed_tests       => passed_tests,
    :failed_tests       => failed_tests
  }
end

def print_test_results_summary(results)
  puts 'OSCAP RESULTS SUMMARY:'
  total = results[:failed_tests].size + results[:passed_tests].size
  puts "#{total} Total Tests with 'idref' ~= '#{results[:rule_search_string]}'"
  printf("%10d tests passed\n", results[:passed_tests].size)
  printf("%10d tests failed\n", results[:failed_tests].size)
  puts
  puts 'Failed Tests:'
  results[:failed_tests].each do |rule_result|
    puts '  ' + rule_result.attribute('idref').value
  end
end

test_name 'Check OSCAP for stig profile'

describe 'run oscap against the appropriate fixtures for stig audit profile' do

  hosts.each do |host|
    context "on #{host}" do
      before(:all) do
        @ssg = Simp::BeakerHelpers::SSG.new(host)
      end

      it 'should run oscap and retrive the report in xml and html format' do
        os = fact_on(host, 'operatingsystemmajrelease')
        profile = "rhel#{os}-disa"
        @ssg.evaluate(profile)
      end

      it 'should not have any failing tests' do
        # 3 tests erroneously fail
        # - 'Ensure auditd Collects Information on Kernel Module Unloading - rmmod'
        #   - oscap check is missing auid filter present in the STIG
        #   - xccdf_org.ssgproject.content_rule_audit_rules_kernel_module_loading_rmmod'
        #   - STIG ID RHEL-07-030850
        # - 'Ensure auditd Collects Information on Kernel Module Loading and Unloading - modprobe'
        #   - oscap check is missing auid filter present in the STIG
        #   - xccdf_org.ssgproject.content_rule_audit_rules_kernel_module_loading_modprobe
        #   - STIG ID RHEL-07-030860
        # - 'Ensure auditd Collects Information on Kernel Module Loading - insmod'
        #   - oscap check is missing auid filter present in the STIG
        #   - xccdf_org.ssgproject.content_rule_audit_rules_kernel_module_loading_insmod
        #   - STIG ID RHEL-07-030840
        #
        # 1 test fails and whether a change is warranted is TBD
        # - 'Ensure auditd Collects Information on the Use of Privileged Commands'
        #   - oscap check says not conformant, when every file with setuid/setgid
        #     has an audit rule. Could be the rules for /usr/bin/mount are a problem:
        #     - These rules don't have '-F perm=x'.
        #     - These rules have arch=* specifiers which would break an exact match.
        #   - xccdf_org.ssgproject.content_rule_audit_rules_privileged_commands
        #   - STIG ID RHEL-07-030360
        pending 'OSCAP checks are incorrect'
        results = get_oscap_test_results('_audit_')
        print_test_results_summary(results)
        expect(results[:failed_tests].size).to eq 0
      end
    end
  end
end
