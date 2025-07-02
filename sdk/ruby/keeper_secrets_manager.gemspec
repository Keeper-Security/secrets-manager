require_relative 'lib/keeper_secrets_manager/version'

Gem::Specification.new do |spec|
  spec.name          = 'keeper_secrets_manager'
  spec.version       = KeeperSecretsManager::VERSION
  spec.authors       = ['Keeper Security']
  spec.email         = ['sm@keepersecurity.com']

  spec.summary       = 'Keeper Secrets Manager SDK for Ruby'
  spec.description   = 'Ruby SDK for Keeper Secrets Manager - A zero-knowledge platform for managing and protecting infrastructure secrets'
  spec.homepage      = 'https://github.com/Keeper-Security/secrets-manager'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 2.6.0'

  spec.metadata['allowed_push_host'] = 'https://rubygems.org'
  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/Keeper-Security/secrets-manager'
  spec.metadata['changelog_uri'] = 'https://github.com/Keeper-Security/secrets-manager/blob/master/CHANGELOG.md'

  # Specify which files should be added to the gem when it is released.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  # Runtime dependencies
  # No required runtime dependencies - base32 is optional for TOTP support
  
  # All development dependencies are in Gemfile
end