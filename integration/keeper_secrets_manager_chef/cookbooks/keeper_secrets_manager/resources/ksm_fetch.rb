unified_mode true

provides :ksm_fetch

property :input_path, String,
         description: 'Path to input.json file (optional - uses default if not provided)'

property :timeout, Integer,
         default: 300,
         description: 'Timeout for script execution'

property :deploy_path, String,
         default: lazy {
           platform_family?('windows') ? 'C:\ProgramData\keeper_secrets_manager\scripts\ksm.py' : '/opt/keeper_secrets_manager/scripts/ksm.py'
         },
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
    cookbook 'keeper_secrets_manager'
    mode '0755'
    action :create
  end

  run_keeper_script
end

action_class do
  def run_keeper_script
    # Prefer python discovered during install (persisted into run_state),
    # then validated candidate (Windows only), then fallback
    python_cmd = node.run_state['ksm_python'] || (platform_family?('windows') ? find_valid_python : nil) || which_python
    script_path = new_resource.deploy_path

    if platform_family?('windows')
      # Quote paths on Windows to handle spaces
      if new_resource.input_path
        full_command = "\"#{python_cmd}\" \"#{script_path}\" --input \"#{new_resource.input_path}\""
        Chef::Log.info("Running Keeper script with: #{new_resource.input_path}")
      else
        full_command = "\"#{python_cmd}\" \"#{script_path}\""
        Chef::Log.info('Running Keeper script with default input.json')
      end
    else
      command_parts = [python_cmd, script_path]
      if new_resource.input_path
        command_parts << '--input'
        command_parts << new_resource.input_path
        Chef::Log.info("Running Keeper script with: #{new_resource.input_path}")
      else
        Chef::Log.info('Running Keeper script with default input.json')
      end
      full_command = command_parts.join(' ')
    end

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
    if platform_family?('windows')
      # Prefer the validated python from find_valid_python (skips WindowsApps shims)
      valid = find_valid_python
      return valid if valid

      # Fallback: try simple where/query and common locations
      %w(python3 python).each do |cmd|
        result = shell_out("where #{cmd}")
        next unless result.exitstatus == 0
        paths = result.stdout.strip.split(/\r?\n/)
        real_path = paths.find { |p| !p.downcase.include?('windowsapps') && ::File.exist?(p) }
        return real_path if real_path
      end

      common_paths = [
        'C:\Program Files\Python313\python.exe',
        'C:\Program Files\Python312\python.exe',
        "#{ENV['LOCALAPPDATA']}\\Programs\\Python\\Python313\\python.exe",
        "#{ENV['LOCALAPPDATA']}\\Programs\\Python\\Python312\\python.exe",
      ]
      found = common_paths.find { |p| ::File.exist?(p) }
      return found if found
      'python'
    else
      %w(python3 python).each do |cmd|
        result = shell_out("which #{cmd}")
        return cmd if result.exitstatus == 0
      end
      'python3'
    end
  rescue
    platform_family?('windows') ? 'python' : 'python3'
  end

  # --- Encrypted Data Bag Loader ---
  def load_keeper_config
    begin
      # Chef automatically uses encrypted_data_bag_secret from config
      keeper_config = data_bag_item('keeper', 'keeper_config')
      keeper_config['config_json'] || keeper_config['token']
    rescue Net::HTTPClientException, Chef::Exceptions::InvalidDataBagPath, Errno::ENOENT, Chef::Exceptions::SecretNotFound
      Chef::Log.warn('No Encrypted Data Bag found, falling back to KEEPER_CONFIG environment variable')
      ENV['KEEPER_CONFIG']
    end
  end

  # helper: find a real python executable on Windows (avoid WindowsApps shims)
  def find_valid_python
    # Only run this on Windows
    return nil unless platform_family?('windows')
    begin
      %w(python3 python).each do |c|
        res = shell_out("where #{c}")
        next unless res.exitstatus == 0
        candidates = res.stdout.split(/\r?\n/).map(&:strip)
        candidates.each do |p|
          next unless ::File.exist?(p)
          next if p.downcase.include?('windowsapps')
          v = shell_out("\"#{p}\" --version")
          return p if v.exitstatus == 0
        end
      end
    rescue
      nil
    end
    nil
  end
end
