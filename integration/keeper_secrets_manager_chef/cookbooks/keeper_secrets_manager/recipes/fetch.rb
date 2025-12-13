# 
# Cookbook:: keeper_secrets_manager
# Recipe:: fetch
#
# Deploy the input.json file to the instance at runtime using a platform-safe path
target = ::File.join(Chef::Config[:file_cache_path], 'input.json')
directory ::File.dirname(target) do
  recursive true
  action :create
end
cookbook_file target do
  source 'input.json' # looks in files/default/input.json
  owner 'root' unless platform_family?('windows')
  group platform_family?('mac_os_x') ? 'wheel' : (platform_family?('windows') ? nil : 'root')
  mode '0644'
  sensitive true
  action :create
end
# Use the custom ksm_fetch resource to fetch secrets using the input.json
ksm_fetch 'fetch_secrets' do
  input_path target # uses Chef::Config[:file_cache_path] on all platforms
  action :run
end
# Log success
log 'Keeper secrets fetched successfully!' do
  level :info
end