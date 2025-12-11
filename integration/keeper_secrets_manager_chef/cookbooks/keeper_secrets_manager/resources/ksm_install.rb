# Custom resource for installing Keeper Secrets Manager Python SDK via pip
# Completely self-contained with sensible defaults

unified_mode true

provides :ksm_install

# Properties with platform-appropriate defaults
property :python_sdk, [true, false],
         default: true,
         description: 'Install Python SDK (keeper-secrets-manager-core)'

property :cli_tool, [true, false],
         default: false,
         description: 'Install CLI tool (keeper-secrets-manager-cli)'

property :user_install, [true, false],
         default: false,
         description: 'Install for current user only (--user flag)'

property :base_dir, String,
         default: lazy {
           case node['platform_family']
           when 'windows'
             'C:\ProgramData\keeper_secrets_manager'
           when 'mac_os_x'
             '/opt/keeper_secrets_manager'
           else
             '/opt/keeper_secrets_manager'
           end
         },
         description: 'Base directory for all KSM files'

property :install_script, [true, false],
         default: true,
         description: 'Install the enhanced ksm.py script'

# Computed properties (derived from base_dir)
def config_dir
  ::File.join(base_dir, 'config')
end

def scripts_dir
  ::File.join(base_dir, 'scripts')
end

def bin_dir
  ::File.join(base_dir, 'bin')
end

# Actions
action :install do
  install_prerequisites
  upgrade_pip
  install_keeper_packages
  create_directories if new_resource.install_script
  install_scripts if new_resource.install_script

  # --- Encrypted Data Bag: Write config file if config is present ---
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

  verify_installation
end

action :remove do
  remove_keeper_packages
  remove_directories
end

action :upgrade do
  upgrade_keeper_packages
end

action_class do
  def create_directories
    # Create base directory structure
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

    directory scripts_dir do
      recursive true
      mode '0755'
      action :create
    end
  end

  def install_scripts
    # Install our enhanced Python script
    cookbook_file "#{scripts_dir}/ksm.py" do
      source 'ksm.py'
      cookbook 'keeper_secrets_manager'
      mode '0755'
      action :create
    end

    Chef::Log.info("KSM script installed: #{scripts_dir}/ksm.py")
  end

  def remove_directories
    directory new_resource.base_dir do
      recursive true
      action :delete
    end
  end

  def install_prerequisites
    case node['platform_family']
    when 'rhel', 'fedora', 'amazon'
      package %w(python3 python3-pip python3-devel) do
        action :install
      end
    when 'debian'
      package %w(python3 python3-pip python3-dev build-essential) do
        action :install
      end
    when 'suse'
      package %w(python3 python3-pip python3-devel) do
        action :install
      end
    when 'alpine'
      package %w(python3 py3-pip python3-dev build-base) do
        action :install
      end
    when 'mac_os_x'
      execute 'install_python_macos' do
        command 'brew install python3'
        not_if 'which python3'
        only_if 'which brew'
      end
    when 'windows'
      chocolatey_package 'python3' do
        action :install
        not_if 'where python || where python3'
        only_if 'where choco'
      end
    end
  end

  def upgrade_pip
    Chef::Log.info('Upgrading pip to latest version')

    if platform_family?('windows')
      # On Windows, use python -m pip to avoid file locking issues
      python_cmd = python_command('-m pip install --upgrade pip')
      user_flag = new_resource.user_install ? '--user' : ''
      pip_upgrade_cmd = "#{python_cmd} #{user_flag}".strip
    else
      pip_upgrade_cmd = pip_command('install --upgrade pip')
    end

    execute 'upgrade_pip' do
      command pip_upgrade_cmd
      timeout 300
      retries 2
    end
  end

  def install_keeper_packages
    if new_resource.python_sdk
      Chef::Log.info('Installing latest Keeper Python SDK')

      sdk_install_cmd = pip_command('install --upgrade keeper-secrets-manager-core')
      pip_show_cmd = pip_show_command('keeper-secrets-manager-core')

      execute 'install_keeper_sdk' do
        command sdk_install_cmd
        timeout 300
        retries 2
        not_if pip_show_cmd
      end
    end

    if new_resource.cli_tool
      Chef::Log.info('Installing latest Keeper CLI')

      cli_install_cmd = pip_command('install --upgrade keeper-secrets-manager-cli')
      pip_show_cli_cmd = pip_show_command('keeper-secrets-manager-cli')

      execute 'install_keeper_cli' do
        command cli_install_cmd
        timeout 300
        retries 2
        not_if pip_show_cli_cmd
      end
    end
  end

  def verify_installation
    if new_resource.python_sdk
      sdk_test_cmd = python_command('-c "import keeper_secrets_manager_core; print(\'SDK OK\')"')

      execute 'verify_sdk' do
        command sdk_test_cmd
        timeout 30
      end
      Chef::Log.info('Keeper Python SDK verified')
    end

    if new_resource.cli_tool
      cli_test_cmd = python_command('-c "import keeper_secrets_manager_cli; print(\'CLI OK\')"')

      execute 'verify_cli' do
        command cli_test_cmd
        timeout 30
      end
      Chef::Log.info('Keeper CLI verified')
    end

    if new_resource.install_script
      Chef::Log.info("KSM script available at: #{scripts_dir}/ksm.py")
    end
  end

  def remove_keeper_packages
    %w(keeper-secrets-manager-core keeper-secrets-manager-cli).each do |package|
      uninstall_cmd = pip_command("uninstall -y #{package}")
      pip_show_cmd = pip_show_command(package)

      execute "remove_#{package.gsub('-', '_')}" do
        command uninstall_cmd
        only_if pip_show_cmd
      end
    end
    Chef::Log.info('Keeper packages removed')
  end

  def upgrade_keeper_packages
    packages = []
    packages << 'keeper-secrets-manager-core' if new_resource.python_sdk
    packages << 'keeper-secrets-manager-cli' if new_resource.cli_tool

    packages.each do |package|
      upgrade_cmd = pip_command("install --upgrade #{package}")
      pip_show_cmd = pip_show_command(package)

      execute "upgrade_#{package.gsub('-', '_')}" do
        command upgrade_cmd
        only_if pip_show_cmd
      end
    end
    Chef::Log.info('Keeper packages upgraded')
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

  private

  def pip_command(args)
    pip_cmd = which('pip3') || which('pip')
    user_flag = new_resource.user_install ? '--user' : ''

    if pip_cmd
      # pip executable found, use it directly
      if platform_family?('windows')
        # Quote paths on Windows to handle spaces
        "\"#{pip_cmd}\" #{args} #{user_flag}".strip
      else
        "sudo #{pip_cmd} #{args}".strip
      end
    else
      # Fallback to python -m pip (pip not in PATH but Python is available)
      pip_cmd = python_command('-m pip')
      "#{pip_cmd} #{args} #{user_flag}".strip
    end
  end

  def pip_show_command(package)
    pip_cmd = which('pip3') || which('pip')
    if pip_cmd
      if platform_family?('windows')
        # Quote paths on Windows to handle spaces
        "\"#{pip_cmd}\" show #{package}"
      else
        "#{pip_cmd} show #{package}"
      end
    else
      # Fallback to python -m pip (pip not in PATH but Python is available)
      pip_cmd = python_command('-m pip show')
      "#{pip_cmd} #{package}"
    end
  end

  def python_command(args = '')
    cmd = which('python3') || which('python')
    raise 'Python not found' unless cmd
    if platform_family?('windows')
      # Quote paths on Windows to handle spaces
      "\"#{cmd}\" #{args}".strip
    else
      "#{cmd} #{args}".strip
    end
  end

  def which(command)
    if platform_family?('windows')
      result = shell_out("where #{command}")
      if result.exitstatus == 0
        paths = result.stdout.strip.split("\n")
        # Filter out Windows Store stubs
        real_path = paths.find { |p| !p.include?('WindowsApps') }
        return real_path if real_path
      end

      # Check common installation locations only for Python commands
      if command == 'python3' || command == 'python'
        common_paths = [
          'C:\Program Files\Python313\python.exe',
          'C:\Program Files\Python312\python.exe',
          "#{ENV['LOCALAPPDATA']}\\Programs\\Python\\Python313\\python.exe",
          "#{ENV['LOCALAPPDATA']}\\Programs\\Python\\Python312\\python.exe",
        ]
        found = common_paths.find { |p| ::File.exist?(p) }
        return found if found
      end
      nil
    else
      result = shell_out("which #{command}")
      result.exitstatus == 0 ? result.stdout.strip : nil
    end
  rescue
    nil
  end
end
