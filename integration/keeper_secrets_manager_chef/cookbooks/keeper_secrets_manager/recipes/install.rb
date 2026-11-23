#
# Cookbook:: keeper_secrets_manager
# Recipe:: install
#
# Completely resource-based installation

# Install Keeper Python SDK with sensible defaults
ksm_install 'keeper_secrets_manager' do
  user_install platform_family?('mac_os_x')
  action :install
end

log 'Keeper Secrets Manager installation complete!' do
  level :info
end
