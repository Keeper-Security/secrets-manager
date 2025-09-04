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

    pip_upgrade_cmd = pip_command('install --upgrade pip')

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
      # keeper_config = data_bag_item('keeper', 'keeper_config', IO.read('/etc/chef/encrypted_data_bag_secret'))
      # keeper_config['config_json'] || keeper_config['token']

      secret = Chef::EncryptedDataBagItem.load_secret('/etc/chef/encrypted_data_bag_secret')
      keeper_config = data_bag_item('keeper', 'keeper_config', secret)
      keeper_config['config_json'] || keeper_config['token']
    rescue Net::HTTPClientException, Chef::Exceptions::InvalidDataBagPath, Errno::ENOENT
      Chef::Log.warn('No Encrypted Data Bag or environment variable found for KEEPER_CONFIG!')
      ENV['KEEPER_CONFIG']
    end
  end

  private

  def pip_command(args)
    pip_cmd = which('pip3') || which('pip') || python_command('-m pip')
    user_flag = new_resource.user_install ? '--user' : ''

    if platform_family?('windows') && new_resource.user_install
      "#{pip_cmd} #{args} #{user_flag}".strip
    else
      "sudo #{pip_cmd} #{args}".strip
    end
  end

  def pip_show_command(package)
    pip_cmd = which('pip3') || which('pip')
    "#{pip_cmd} show #{package}"
  end

  def python_command(args = '')
    cmd = which('python3') || which('python')
    raise 'Python not found' unless cmd
    "#{cmd} #{args}".strip
  end

  def which(command)
    if platform_family?('windows')
      result = shell_out("where #{command}")
      result.exitstatus == 0 ? result.stdout.strip.split("\n").first : nil
    else
      result = shell_out("which #{command}")
      result.exitstatus == 0 ? result.stdout.strip : nil
    end
  rescue
    nil
  end
end
