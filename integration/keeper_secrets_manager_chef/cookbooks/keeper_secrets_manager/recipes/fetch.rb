#
# Cookbook:: keeper_secrets_manager
# Recipe:: fetch
#

# Deploy the input.json file to the instance at runtime
cookbook_file '/tmp/input.json' do
  source 'input.json'                    # looks in files/default/input.json
  owner node['platform_family'] == 'mac_os_x' ? 'root' : 'root'
  group node['platform_family'] == 'mac_os_x' ? 'wheel' : 'root'
  mode '0644'
  sensitive true
end

# Use the custom ksm_fetch resource to fetch secrets using the input.json
ksm_fetch 'fetch_secrets' do
  input_path '/tmp/input.json'           # This path now exists in the instance
  action :run
end

# Log success
log 'Keeper secrets fetched successfully!' do
  level :info
end
