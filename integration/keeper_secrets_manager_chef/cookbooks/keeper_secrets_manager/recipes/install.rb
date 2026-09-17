#
# Cookbook:: keeper_secrets_manager
# Recipe:: install
#
# Completely resource-based installation

# Install the Keeper Ruby SDK gem with sensible defaults
ksm_install 'keeper_secrets_manager' do
  action :install
end

log 'Keeper Secrets Manager installation complete!' do
  level :info
end
