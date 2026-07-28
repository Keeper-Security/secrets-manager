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
  spec.required_ruby_version = '>= 3.1.0'

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

  # base64 and logger were default gems through Ruby 3.x; Ruby 4.0 unbundled them.
  # Both are maintained by the Ruby core team — declaring them makes the implicit explicit.
  spec.add_runtime_dependency 'base64'
  spec.add_runtime_dependency 'logger'

  # All development dependencies are in Gemfile
end
