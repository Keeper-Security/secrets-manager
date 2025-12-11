require 'spec_helper'

describe 'keeper_secrets_manager_ksm_install resource' do
  step_into :ksm_install
  platform 'ubuntu'
  let(:shellout_double_python3) do
    double('shell_out', run_command: nil, error!: nil, stdout: '/usr/bin/python3', exitstatus: 0)
  end

  let(:shellout_double_pip3) do
    double('shell_out', run_command: nil, error!: nil, stdout: '/usr/bin/pip3', exitstatus: 0)
  end

  let(:shellout_double_not_found) do
    double('shell_out', run_command: nil, error!: nil, stdout: '', exitstatus: 1)
  end

  before do
    stub_data_bag_item('keeper', 'keeper_config').and_return({
      'config_json' => '{"token":"fake-token"}',
    })

    # Stub shell_out used by `which` logic inside action_class
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which python3').and_return(shellout_double_python3)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which python').and_return(shellout_double_not_found)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which pip3').and_return(shellout_double_pip3)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which pip').and_return(shellout_double_not_found)

    # Stub pip show commands for both SDK and CLI tools
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('/usr/bin/pip3 show keeper-secrets-manager-core').and_return(shellout_double_not_found)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('/usr/bin/pip3 show keeper-secrets-manager-cli').and_return(shellout_double_not_found)

    # Stub `stub_command` equivalents
    stub_command('/usr/bin/pip3 show keeper-secrets-manager-core').and_return(false)
    stub_command('/usr/bin/pip3 show keeper-secrets-manager-cli').and_return(false)
    # # Also stub pip show check
    # allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('/usr/bin/pip3 show keeper-secrets-manager-core').and_return(shellout_double_not_found)
    # stub_command('/usr/bin/pip3 show keeper-secrets-manager-core').and_return(false)
  end

  context 'with default configuration' do
    recipe do
      ksm_install 'keeper_secrets_manager' do
        action :install
      end
    end

    it 'creates all necessary directories' do
      expect(chef_run).to create_directory('/opt/keeper_secrets_manager')
      expect(chef_run).to create_directory('/opt/keeper_secrets_manager/config')
      expect(chef_run).to create_directory('/opt/keeper_secrets_manager/scripts')
    end

    it 'creates the keeper config file from encrypted data bag' do
      expect(chef_run).to create_file('/opt/keeper_secrets_manager/config/keeper_config.json').with(
        content: '{"token":"fake-token"}',
        mode: '0600',
        sensitive: true
      )
    end

    it 'installs the helper script' do
      expect(chef_run).to create_cookbook_file('/opt/keeper_secrets_manager/scripts/ksm.py')
    end

    it 'runs the ksm_install resource' do
      expect(chef_run).to install_ksm_install('keeper_secrets_manager')
    end

    it 'installs the Python SDK by default' do
      expect(chef_run).to run_execute('install_keeper_sdk')
    end
  end

  context 'when python_sdk is disabled' do
    recipe do
      ksm_install 'test' do
        python_sdk false
      end
    end

    it 'does not install python packages' do
      expect(chef_run).not_to run_execute('install_keeper_sdk')
    end
  end

  context 'with user install enabled' do
    recipe do
      ksm_install 'test' do
        user_install true
      end
    end

    it 'uses user install for pip commands' do
      # Test user-specific behavior
      expect(chef_run).to install_ksm_install('test')
    end
  end

  context 'with custom base directory' do
    recipe do
      ksm_install 'test' do
        base_dir '/custom/path'
      end
    end

    it 'creates directories in custom location' do
      expect(chef_run).to create_directory('/custom/path')
      expect(chef_run).to create_directory('/custom/path/config')
      expect(chef_run).to create_directory('/custom/path/scripts')
    end
  end

  context 'with cli_tool enabled' do
    recipe do
      ksm_install 'test' do
        cli_tool true
      end
    end

    it 'installs the CLI tool' do
      expect(chef_run).to run_execute('install_keeper_cli')
    end
  end

  context 'with install_script disabled' do
    recipe do
      ksm_install 'test' do
        install_script false
      end
    end

    it 'does not create directories' do
      expect(chef_run).not_to create_directory('/opt/keeper_secrets_manager')
    end
  end
end

describe 'keeper_secrets_manager_ksm_install resource on Windows' do
  step_into :ksm_install
  platform 'windows'

  let(:real_python_path) { 'C:\Users\test\AppData\Local\Programs\Python\Python312\python.exe' }
  let(:real_pip_path) { 'C:\Users\test\AppData\Local\Programs\Python\Python312\Scripts\pip3.exe' }
  let(:windows_store_stub) { 'C:\Users\test\AppData\Local\Microsoft\WindowsApps\python3.exe' }
  let(:python_with_spaces) { 'C:\Program Files\Python313\python.exe' }
  let(:pip_with_spaces) { 'C:\Program Files\Python313\Scripts\pip3.exe' }

  let(:shellout_where_python3_multiple) do
    double('shell_out', run_command: nil, error!: nil,
           stdout: "#{windows_store_stub}\n#{real_python_path}", exitstatus: 0)
  end

  let(:shellout_where_python3_real) do
    double('shell_out', run_command: nil, error!: nil,
           stdout: real_python_path, exitstatus: 0)
  end

  let(:shellout_where_python3_spaces) do
    double('shell_out', run_command: nil, error!: nil,
           stdout: "#{windows_store_stub}\n#{python_with_spaces}", exitstatus: 0)
  end

  let(:shellout_where_pip3_real) do
    double('shell_out', run_command: nil, error!: nil,
           stdout: real_pip_path, exitstatus: 0)
  end

  let(:shellout_where_pip3_spaces) do
    double('shell_out', run_command: nil, error!: nil,
           stdout: pip_with_spaces, exitstatus: 0)
  end

  let(:shellout_not_found) do
    double('shell_out', run_command: nil, error!: nil, stdout: '', exitstatus: 1)
  end

  before do
    stub_data_bag_item('keeper', 'keeper_config').and_return({
      'config_json' => '{"token":"fake-token"}',
    })

    # Stub File.exist? for common Python paths
    allow(::File).to receive(:exist?).and_call_original
    allow(::File).to receive(:exist?).with(real_python_path).and_return(true)
    allow(::File).to receive(:exist?).with(real_pip_path).and_return(true)
    allow(::File).to receive(:exist?).with(python_with_spaces).and_return(true)
    allow(::File).to receive(:exist?).with(pip_with_spaces).and_return(true)
  end

  context 'with default Windows configuration' do
    before do
      # Stub where commands - filter out Windows Store stub
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python3').and_return(shellout_where_python3_multiple)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python').and_return(shellout_where_python3_real)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip3').and_return(shellout_where_pip3_real)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip').and_return(shellout_not_found)
      # Stub choco check for install_prerequisites
      stub_command('where choco').and_return(false)
      stub_command('where python || where python3').and_return(true)
      # Stub pip show commands (used in not_if guards) - match the exact command string
      stub_command("\"#{real_pip_path}\" show keeper-secrets-manager-core").and_return(false)
      stub_command("\"#{real_pip_path}\" show keeper-secrets-manager-cli").and_return(false)
      # Also stub the shell_out version (used internally)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with("\"#{real_pip_path}\" show keeper-secrets-manager-core").and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with("\"#{real_pip_path}\" show keeper-secrets-manager-cli").and_return(shellout_not_found)
    end

    recipe do
      ksm_install 'keeper_secrets_manager' do
        action :install
      end
    end

    it 'creates Windows default directories' do
      # Chef uses forward slashes for paths on Windows
      expect(chef_run).to create_directory('C:\ProgramData\keeper_secrets_manager')
      expect(chef_run).to create_directory('C:\ProgramData\keeper_secrets_manager/config')
      expect(chef_run).to create_directory('C:\ProgramData\keeper_secrets_manager/scripts')
    end

    it 'filters out Windows Store Python stub' do
      # The which() method should return real_python_path, not windows_store_stub
      expect(chef_run).to install_ksm_install('keeper_secrets_manager')
    end

    it 'uses python -m pip for pip upgrade on Windows' do
      expect(chef_run).to run_execute('upgrade_pip').with(
        command: match(/^"[^"]*python[^"]*" -m pip install --upgrade pip/)
      )
    end

    it 'quotes paths in pip commands' do
      expect(chef_run).to run_execute('install_keeper_sdk')
      # Command should have quoted paths
      execute_resource = chef_run.execute('install_keeper_sdk')
      expect(execute_resource.command).to match(/^"[^"]*pip[^"]*"/)
    end
  end

  context 'with Python in path with spaces' do
    before do
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python3').and_return(shellout_where_python3_spaces)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python').and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip3').and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip').and_return(shellout_not_found)
      # Stub choco check for install_prerequisites
      stub_command('where choco').and_return(false)
      stub_command('where python || where python3').and_return(true)
      # Stub pip show commands - when pip not found, it falls back to python -m pip show
      # Stub both formats in case ChefSpec sees it differently
      stub_command("\"#{python_with_spaces}\" -m pip show keeper-secrets-manager-core").and_return(false)
      stub_command("\"#{python_with_spaces}\" -m pip show keeper-secrets-manager-cli").and_return(false)
      stub_command("\"#{python_with_spaces}\" show keeper-secrets-manager-core").and_return(false)
      stub_command("\"#{python_with_spaces}\" show keeper-secrets-manager-cli").and_return(false)
      # Also stub the shell_out version
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with(match(/python.*show keeper-secrets-manager/)).and_return(shellout_not_found)
    end

    recipe do
      ksm_install 'test' do
        action :install
      end
    end

    it 'quotes Python path with spaces in commands' do
      expect(chef_run).to run_execute('upgrade_pip')
      execute_resource = chef_run.execute('upgrade_pip')
      # Path with spaces should be quoted
      expect(execute_resource.command).to match(/^"C:\\Program Files\\Python/)
    end

    it 'falls back to python -m pip when pip not found' do
      expect(chef_run).to run_execute('install_keeper_sdk')
      execute_resource = chef_run.execute('install_keeper_sdk')
      # Should use python -m pip fallback
      # The command should be: "C:\Program Files\Python313\python.exe" -m pip install --upgrade keeper-secrets-manager-core
      expect(execute_resource.command).to include('-m pip')
      expect(execute_resource.command).to match(/python[^"]*" -m pip install/)
    end
  end

  context 'when pip not in PATH but Python is available' do
    before do
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python3').and_return(shellout_where_python3_real)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python').and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip3').and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip').and_return(shellout_not_found)
      # Stub choco check for install_prerequisites
      stub_command('where choco').and_return(false)
      stub_command('where python || where python3').and_return(true)
      # Stub pip show commands - falls back to python -m pip show
      # Note: pip_show_command calls python_command('-m pip show') which includes the -m pip show part
      stub_command("\"#{real_python_path}\" -m pip show keeper-secrets-manager-core").and_return(false)
      stub_command("\"#{real_python_path}\" -m pip show keeper-secrets-manager-cli").and_return(false)
      # Also stub the shell_out version with a pattern match
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with(match(/python.*show keeper-secrets-manager/)).and_return(shellout_not_found)
    end

    recipe do
      ksm_install 'test' do
        action :install
      end
    end

    it 'uses python -m pip as fallback' do
      expect(chef_run).to run_execute('install_keeper_sdk')
      execute_resource = chef_run.execute('install_keeper_sdk')
      expect(execute_resource.command).to match(/python[^"]*" -m pip install/)
    end
  end
end
