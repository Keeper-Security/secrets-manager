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

  # Re-check whether Python is available in this run
  python_available = !!(node.run_state['ksm_python'] || find_python_executable || which('python3') || which('python'))

  if python_available
    upgrade_pip
    install_keeper_packages
  else
    Chef::Log.warn('Python not found after prerequisites step. Skipping pip upgrade and package installation for this run. Re-run chef-solo (or open a new shell) to complete installation once PATH is available.')
  end

  # Always create directories and install script artifacts even if Python isn't yet runnable
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

  # Only attempt verification if Python is available
  verify_installation if python_available
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
      # Windows: prefer existing Python, then Chocolatey, then official installer fallback
      if which('python') || which('python3')
        Chef::Log.info('Python already installed on Windows')
      else
        target_version = '3.11.7' # Specify desired Python version here

        # Detect Windows CPU architecture and choose correct installer suffix
        arch = begin
                 # prefer PROCESSOR_ARCHITEW6432 on WOW64 processes
                 proc_arch = ENV['PROCESSOR_ARCHITEW6432'] || ENV['PROCESSOR_ARCHITECTURE'] || ''
                 proc_arch = proc_arch.downcase
                 proc_arch
               rescue
                 ''
               end

        suffix = case arch
                 when /arm64/i
                   '-arm64.exe'
                 when /amd64|x86_64|x64/i
                   '-amd64.exe'
                 when /x86|i386|32/i
                   '.exe' # upstream 32-bit installer usually has no arch suffix
                 else
                   # fallback: prefer amd64 on modern systems, but log a warning
                   Chef::Log.warn("Unknown Windows processor architecture '#{arch}', defaulting to amd64 installer")
                   '-amd64.exe'
                 end

        # Build installer URL using chosen suffix
        installer_url = "https://www.python.org/ftp/python/#{target_version}/python-#{target_version}#{suffix}"

        Chef::Log.warn("Choco unavailable. Falling back to installing Python #{target_version} using `windows_package`.")

        windows_package 'Python Installer' do
          # The package name is what you will see in 'Add or Remove Programs'
          package_name "Python #{target_version} (64-bit)"
          source installer_url
          # The installer arguments for a silent, all-user install that updates the PATH
          installer_type :custom
          options '/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1'
          # Only run if python isn't already found
          not_if { which('python') || which('python3') }

          # Use a ruby_block to find and update the PATH immediately after installation
          notifies :run, 'ruby_block[discover_installed_python]', :immediately
        end

        # Block to discover and register the newly installed Python in run_state
        find_python_block = proc do
          @discovered_python = find_python_executable
          if @discovered_python
            python_dir = ::File.dirname(@discovered_python)
            # Update ENV['PATH'] for subsequent resources in this Chef run
            ENV['PATH'] = "#{python_dir};#{ENV['PATH']}"
            node.run_state['ksm_python'] = @discovered_python
            Chef::Log.info("Installed Python via windows_package and added #{python_dir} to PATH.")
          else
            Chef::Log.warn('Python installed, but the executable could not be located immediately.')
          end
        end

        ruby_block 'discover_installed_python' do
          action :nothing # This block is only triggered by the windows_package notification
          block(&find_python_block)
        end
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
    elsif platform_family?('mac_os_x') && new_resource.user_install
      # For macOS, we need --break-system-packages even with --user when upgrading pip
      pip_upgrade_cmd = pip_command('install --upgrade pip --break-system-packages')
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
    # On macOS, we need --break-system-packages even with --user
    macos_flag = platform_family?('mac_os_x') && new_resource.user_install ? '--break-system-packages' : ''

    if pip_cmd
      # pip executable found, use it directly
      if platform_family?('windows')
        # Quote paths on Windows to handle spaces
        "\"#{pip_cmd}\" #{args} #{user_flag}".strip
      elsif new_resource.user_install
        # On macOS/Linux: skip sudo if user_install is true OR if running as root
        "#{pip_cmd} #{args} #{user_flag} #{macos_flag}".strip
      elsif Process.uid == 0 # Running as root (uid 0)
        "#{pip_cmd} #{args}".strip
      else
        "sudo #{pip_cmd} #{args}".strip
      end
    else
      # Fallback to python -m pip (pip not in PATH but Python is available)
      pip_cmd = python_command('-m pip')
      "#{pip_cmd} #{args} #{user_flag} #{macos_flag}".strip
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
    # Prefer any previously discovered Python executable (set by find_python_executable)
    @discovered_python ||= find_python_executable
    cmd = @discovered_python || which('python3') || which('python')
    raise 'Python not found' unless cmd
    if platform_family?('windows')
      "\"#{cmd}\" #{args}".strip
    else
      "#{cmd} #{args}".strip
    end
  end

  def which(command)
    if platform_family?('windows')
      # Use `where` to get candidates, but validate each candidate by running `--version`.
      result = shell_out("where #{command}")
      if result.exitstatus == 0
        candidates = result.stdout.split(/\r?\n/).map(&:strip)
        candidates.each do |p|
          next unless ::File.exist?(p)
          # Skip App Execution Aliases / Microsoft Store shims which live under ...WindowsApps...
          next if p.downcase.include?('windowsapps')
          begin
            ver = shell_out("\"#{p}\" --version")
            return p if ver.exitstatus == 0
          rescue
            next
          end
        end
      end

      # fallback: check common installation locations and validate them
      if %w(python python3 pip pip3).include?(command)
        common_paths = [
          'C:\\Program Files\\Python\\Python39\\python.exe',
          'C:\\Program Files\\Python\\Python310\\python.exe',
          'C:\\Program Files\\Python\\Python311\\python.exe',
          "#{ENV['LOCALAPPDATA']}\\Programs\\Python\\Python39\\python.exe",
          "#{ENV['LOCALAPPDATA']}\\Programs\\Python\\Python310\\python.exe",
          "#{ENV['LOCALAPPDATA']}\\Programs\\Python\\Python311\\python.exe",
        ]
        common_paths.each do |p|
          next unless p && ::File.exist?(p)
          begin
            ver = shell_out("\"#{p}\" --version")
            return p if ver.exitstatus == 0
          rescue
            next
          end
        end
      end

      nil
    else
      result = shell_out("which #{command}")
      result.exitstatus == 0 ? result.stdout.strip : nil
    end
  rescue
    nil
  end

  # Find a real python executable on Windows (avoid Windows Store shims) and validate it.
  def find_python_executable
    # Prefer any validated `where`/common candidates first
    return which('python3') if which('python3')
    return which('python') if which('python')

    candidates = []
    # Chocolatey typical locations
    candidates.concat(Dir.glob('C:/ProgramData/chocolatey/bin/python*.exe'))
    candidates.concat(Dir.glob('C:/ProgramData/chocolatey/lib/python*/**/python.exe'))
    # Other common installer locations
    candidates.concat(Dir.glob('C:/Program Files/Python*/python.exe'))
    candidates.concat(Dir.glob("#{ENV['LOCALAPPDATA']}\\Programs\\Python\\Python*\\python.exe")) if ENV['LOCALAPPDATA']
    candidates.concat(Dir.glob('C:/tools/**/python.exe'))
    candidates.concat(Dir.glob('C:/Python*/python.exe'))

    # Deduplicate and validate candidates (skip WindowsApps shims)
    candidates.map! { |p| p && p.strip }.compact!
    candidates.uniq!

    candidates.each do |p|
      next unless ::File.exist?(p)
      next if p.downcase.include?('windowsapps')
      begin
        out = shell_out("\"#{p}\" --version")
        return p if out.exitstatus == 0
      rescue
        next
      end
    end

    nil
  end
end
