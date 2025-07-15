# Cookbook:: keeper_secrets_manager
# Recipe:: demo

# Fetch secrets from Keeper Vault using the custom resource
ksm_fetch 'fetch_secrets' do
  input_path '/Users/yashsolanki/Documents/chef-repo/cookbooks/keeper_secrets_manager/files/default/input.json'
  action :run
end

log 'Keeper secrets fetched successfully !' do
  level :info
end
