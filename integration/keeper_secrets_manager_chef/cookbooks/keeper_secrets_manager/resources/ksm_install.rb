# Custom resource for installing the Keeper Secrets Manager Ruby SDK gem.

unified_mode true

provides :ksm_install

property :base_dir, String,
         default: lazy { node['keeper_secrets_manager']['base_dir'] },
         description: 'Base directory for the Keeper config file'

property :sdk_version, String,
         default: '17.2.1',
         description: 'Pinned keeper_secrets_manager gem version'

def config_dir
  ::File.join(base_dir, 'config')
end

action :install do
  chef_gem 'keeper_secrets_manager' do
    version new_resource.sdk_version
    compile_time false
    action :install
  end

  directory new_resource.base_dir do
    recursive true
    mode '0755'
    action :create
  end

  directory config_dir do
    recursive true
    mode '0755'
    action :create
  end

  keeper_config = load_keeper_config
  if keeper_config
    file "#{config_dir}/keeper_config.json" do
      content keeper_config
      mode '0600'
      sensitive true
      action :create
    end
  else
    Chef::Log.warn('No Keeper config found in encrypted data bag or environment variable. Skipping config file creation.')
  end
end

action :remove do
  chef_gem 'keeper_secrets_manager' do
    action :remove
  end

  directory new_resource.base_dir do
    recursive true
    action :delete
  end
end

action :upgrade do
  chef_gem 'keeper_secrets_manager' do
    version new_resource.sdk_version
    compile_time false
    action :upgrade
  end
end

action_class do
  include KeeperSecretsManagerCookbook::Helpers
end
