Gem::Specification.new do |spec|
  spec.name = "authservice"
  spec.version = "0.1.0"
  spec.summary = "Generated Ruby SDK and Rails middleware for AuthService"
  spec.license = "MIT"
  spec.files = Dir["lib/**/*.rb", "README.md"]
  spec.require_paths = ["lib"]
  spec.add_dependency "jwt", ">= 2.8"
  spec.add_dependency "faraday", ">= 2.0"
end
