require 'json'
require 'fileutils'

unified_mode true

provides :ksm_fetch

property :input_path, String,
         description: 'Path to input.json file (optional - uses default if not provided)'

property :base_dir, String,
         default: lazy { node['keeper_secrets_manager']['base_dir'] },
         description: 'Base directory holding input.json and, for the token auth method, the persisted config file'

action :run do
  # The keeper_secrets_manager gem is installed by ksm_install's chef_gem
  # resource at converge time, so this require must stay inside the action
  # block, not at the top of the file - a top-of-file require runs at
  # compile time, before ksm_install's chef_gem has had a chance to run.
  require 'keeper_secrets_manager'

  path = new_resource.input_path || ::File.join(new_resource.base_dir, 'input.json')
  raise "Input file not found: #{path}" unless ::File.exist?(path)

  config = ::JSON.parse(::File.read(path))
  sm = build_secrets_manager(config['authentication'])

  Array(config['secrets']).each do |entry|
    keeper_notation, output_name, action_type = parse_secret_notation(entry)
    value = sm.get_notation("keeper://#{keeper_notation}")

    case action_type
    when :env
      ENV[output_name] = value.to_s
      Chef::Log.info("Keeper secret exported to ENV['#{output_name}']")
    when :file
      ::FileUtils.mkdir_p(::File.dirname(output_name))
      # Write-then-rename, not write-then-chmod: a plain File.binwrite
      # would follow a pre-existing symlink at output_name (writing the
      # secret through it) and briefly leave the file at the default
      # umask before the chmod line ran. rename(2) replaces whatever is
      # at the destination - including an attacker's symlink - without
      # ever following it, and the temp file is already at 0600 before
      # it's visible at output_name, so there's no window either way.
      temp_path = "#{output_name}.tmp.#{Process.pid}"
      ::File.open(temp_path, ::File::WRONLY | ::File::CREAT | ::File::EXCL | ::File::BINARY, 0o600) do |f|
        f.write(value)
      end
      ::File.rename(temp_path, output_name)
      Chef::Log.info("Keeper secret written to #{output_name}")
    else
      node.run_state['keeper_secrets'] ||= {}
      node.run_state['keeper_secrets'][output_name] = value
      Chef::Log.info("Keeper secret stored in node.run_state['keeper_secrets']['#{output_name}']")
    end
  end

  Chef::Log.info('Keeper secrets fetched successfully')
end

action_class do
  include KeeperSecretsManagerCookbook::Helpers

  # input.json's "authentication" array is [method, value]. Where that value
  # comes from depends on the method:
  #
  # - base64: value is never read from input.json itself (that file is
  #   deployed at mode 0644 by recipes/fetch.rb, so it's not a safe place for
  #   a persistent vault credential). Sourced from load_keeper_config instead
  #   (encrypted data bag, falling back to KEEPER_CONFIG env).
  # - token: value is the one-time token literally, taken from input.json -
  #   a token is meant to be handed over inline and is single-use, unlike a
  #   base64 config. The bound result persists to base_dir/config so a spent
  #   token is never reused on the next run.
  # - json: value is a literal config file path, taken from input.json,
  #   never overridden by KEEPER_CONFIG - the old Python script's env-first
  #   check applied to every method regardless of which one was requested,
  #   which meant an unrelated ambient env var could silently hijack a
  #   json-configured run.
  def build_secrets_manager(auth_config)
    method = Array(auth_config).first

    case method
    when 'base64'
      config_value = load_keeper_config
      unless config_value
        raise 'No Keeper config found in encrypted data bag or KEEPER_CONFIG environment variable'
      end

      ::KeeperSecretsManager::Core::SecretsManager.new(
        config: ::KeeperSecretsManager::Storage::InMemoryStorage.new(config_value)
      )
    when 'token'
      token = Array(auth_config)[1]
      raise "authentication method 'token' requires the one-time token as the second element" if token.to_s.empty?

      persisted_config_path = ::File.join(new_resource.base_dir, 'config', 'keeper_config.json')
      ::KeeperSecretsManager::Core::SecretsManager.new(
        config: ::KeeperSecretsManager::Storage::FileStorage.new(persisted_config_path),
        token: token
      )
    when 'json'
      config_path = Array(auth_config)[1]
      raise "authentication method 'json' requires a config file path as the second element" if config_path.to_s.empty?

      ::KeeperSecretsManager::Core::SecretsManager.new(
        config: ::KeeperSecretsManager::Storage::FileStorage.new(config_path)
      )
    else
      raise ArgumentError, "Unsupported authentication method: #{method.inspect}"
    end
  end
end
