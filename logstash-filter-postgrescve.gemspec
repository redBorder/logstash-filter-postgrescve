Gem::Specification.new do |s|
  s.name          = 'logstash-filter-postgrescve'
  s.version       = '0.1.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Custom filter plugin for enriching events with PostgreSQL CVE data'
  s.description   = 'A Logstash filter plugin that queries PostgreSQL CVE data'
  s.authors       = ['redBorder']
  s.email         = ['systems@redborder.com']
  s.homepage      = 'https://redborder.com'
  s.require_paths = ['lib']

  s.files         = Dir['lib/**/*']
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  s.metadata = {"logstash_plugin" => "true", "logstash_group" => "filter"}

  s.add_runtime_dependency 'logstash-core-plugin-api', '~> 2.0'
end
