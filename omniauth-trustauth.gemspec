# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)
require 'omniauth-trustauth/version'

Gem::Specification.new do |gem|
  gem.authors       = ["romaimperator"]
  gem.email         = ["romaimperator@gmail.com"]
  gem.description   = %q{An OmniAuth strategy for allowing TrustAuth authentication.}
  gem.summary       = %q{An OmniAuth strategy for allowing TrustAuth authentication.}
  gem.homepage      = "http://trustauth.com"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "omniauth-trustauth"
  gem.require_paths = ["lib"]
  gem.version       = OmniAuth::TrustAuth::VERSION

  gem.add_dependency "omniauth", "~> 1.0"
  gem.add_dependency "multi_json"
end
