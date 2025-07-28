unified_mode true

provides :ksm_fetch

property :input_path, String,
         description: 'Path to input.json file (optional - uses default if not provided)'

property :timeout, Integer,
         default: 300,
         description: 'Timeout for script execution'

property :deploy_path, String,
         default: '/opt/keeper_secrets_manager/ksm.py',
         description: 'Where to deploy the script for execution'

action :run do
  # Check input file if provided
  if new_resource.input_path
    unless ::File.exist?(new_resource.input_path)
      raise "Input file not found: #{new_resource.input_path}"
    end
  end

  # Always deploy the script from the cookbook to a known location
  cookbook_file new_resource.deploy_path do
    source 'ksm.py'
    mode '0755'
    action :create
  end

  run_keeper_script
end

action_class do
  def run_keeper_script
    python_cmd = which_python
    script_path = new_resource.deploy_path
    command_parts = [python_cmd, script_path]

    if new_resource.input_path
      command_parts << '--input'
      command_parts << new_resource.input_path
      Chef::Log.info("Running Keeper script with: #{new_resource.input_path}")
    else
      Chef::Log.info('Running Keeper script with default input.json')
    end

    full_command = command_parts.join(' ')

    # Load Keeper config from data bag or ENV
    keeper_config = load_keeper_config

    execute "keeper_fetch_#{new_resource.name}" do
      command full_command
      timeout new_resource.timeout
      live_stream true
      environment('PYTHONUNBUFFERED' => '1', 'KEEPER_CONFIG' => keeper_config)
    end

    Chef::Log.info('Keeper script completed')
  end

  def which_python
    %w(python3 python).each do |cmd|
      result = shell_out("which #{cmd}")
      return cmd if result.exitstatus == 0
    end
    'python3'
  rescue
    'python3'
  end

  # --- Encrypted Data Bag Loader ---
  def load_keeper_config
    begin
      # keeper_config = data_bag_item('keeper', 'keeper_config', IO.read('/etc/chef/encrypted_data_bag_secret'))
      # keeper_config['config_json'] || keeper_config['token']

      secret = Chef::EncryptedDataBagItem.load_secret('/etc/chef/encrypted_data_bag_secret')
      keeper_config = Chef::EncryptedDataBagItem.load('keeper', 'keeper_config', secret)
      keeper_config['config_json'] || keeper_config['token']

    rescue Net::HTTPServerException, Chef::Exceptions::InvalidDataBagPath, Errno::ENOENT
      Chef::Log.warn('No Encrypted Data Bag or environment variable found for KEEPER_CONFIG!')
      ENV['KEEPER_CONFIG']
    end
  end
end 