# ------------------------------------------------------------------------------
# NOTE: SIMP Puppet rake tasks support ruby 2.1.9
# ------------------------------------------------------------------------------
gem_sources = ENV.fetch('GEM_SERVERS','https://rubygems.org').split(/[, ]+/)

gem_sources.each { |gem_source| source gem_source }

group :test do
  gem 'rake'
  gem 'puppet', ENV.fetch('PUPPET_VERSION',  '~> 4.0')
  gem 'rspec'
  gem 'rspec-puppet'
  gem 'hiera-puppet-helper'
  # For the target in .fixtures.yml
  gem 'puppetlabs_spec_helper', :git => 'https://github.com/puppetlabs/puppetlabs_spec_helper', :ref => 'b049630ac2cfbab96702701e4997ec51c23cf9c0'
  gem 'metadata-json-lint'
  gem 'puppet-strings'
  gem 'puppet-lint-empty_string-check',   :require => false
  gem 'puppet-lint-trailing_comma-check', :require => false
  gem 'simp-rspec-puppet-facts', ENV.fetch('SIMP_RSPEC_PUPPET_FACTS_VERSION', '~> 2.0')
  gem 'simp-rake-helpers', ENV.fetch('SIMP_RAKE_HELPERS_VERSION', '~> 4.0')
end

group :development do
  gem 'travis'
  gem 'travis-lint'
  gem 'travish'
  gem 'puppet-blacksmith'
  gem 'guard-rake'
  gem 'pry'
  gem 'pry-doc'

  # `listen` is a dependency of `guard`
  # from `listen` 3.1+, `ruby_dep` requires Ruby version >= 2.2.3, ~> 2.2
  gem 'listen', '~> 3.0.6'
end

group :system_tests do
  gem 'beaker-rspec'
  gem 'simp-beaker-helpers', ENV.fetch('SIMP_BEAKER_HELPERS_VERSION', '~> 1.7')
end
