#
# Cookbook:: keeper_secrets_manager
# Recipe:: install
#
# Completely resource-based installation

# Install Keeper Python SDK with sensible defaults
ksm_install 'keeper_secrets_manager' do
  user_install node['platform_family'] == 'mac_os_x' ? true : false
  action :install
end

log 'Keeper Secrets Manager installation complete!' do
  level :info
end
