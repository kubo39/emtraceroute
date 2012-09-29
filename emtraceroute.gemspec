lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require_relative 'emtraceroute/version'

Gem::Specification.new do |s|
  s.name          = "emtraceroute"
  s.version       = EM::Traceroute::VERSION
  s.authors       = ["kubo39"]
  s.email         = "kubo39@gmail.com"
  s.description   = %q{traceroute utility on EventMachine}
  s.summary       = s.description
  s.homepage      = "https://github.com/kubo39/emtraceroute"

  s.files         = `git ls-files`.split($/)
  s.executables   = s.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency 'eventmachine'
end
