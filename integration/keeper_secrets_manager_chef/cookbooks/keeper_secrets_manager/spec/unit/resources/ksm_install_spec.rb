require 'spec_helper'
require 'chefspec'
require 'chefspec/solo_runner'

describe 'keeper_secrets_manager::install (ksm_install resource)' do
  let(:runner) { ChefSpec::SoloRunner.new(platform: 'windows', version: '2019') }
  let(:chef_run) do
    runner.converge('keeper_secrets_manager::install')
  end

  before do
    # Provide a safe default for any shell_out calls so tests don't fail on unexpected args
    shellout_not_found = double('shell_out', run_command: nil, error!: nil, stdout: '', exitstatus: 1)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).and_return(shellout_not_found)
  end

  it 'converges the install recipe and declares the ksm_install resource' do
    expect { chef_run }.to_not raise_error
    expect(chef_run).to install_ksm_install('keeper_secrets_manager')
  end
end

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

    # Generic fallback for any shell_out calls not explicitly stubbed
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).and_return(shellout_double_not_found)

    # Specific which/which-like calls on unix
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which python3').and_return(shellout_double_python3)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which python').and_return(shellout_double_not_found)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which pip3').and_return(shellout_double_pip3)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which pip').and_return(shellout_double_not_found)

    # pip show guards - return not found (so installation executes)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with(match(/pip3 show keeper-secrets-manager-core/)).and_return(shellout_double_not_found)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with(match(/pip3 show keeper-secrets-manager-cli/)).and_return(shellout_double_not_found)

    # stub_command equivalents used by ChefSpec for guards
    stub_command('/usr/bin/pip3 show keeper-secrets-manager-core').and_return(false)
    stub_command('/usr/bin/pip3 show keeper-secrets-manager-cli').and_return(false)
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

    it 'declares the resource' do
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

  let(:shellout_where_pip3_real) do
    double('shell_out', run_command: nil, error!: nil,
           stdout: real_pip_path, exitstatus: 0)
  end

  let(:shellout_not_found) do
    double('shell_out', run_command: nil, error!: nil, stdout: '', exitstatus: 1)
  end

  before do
    stub_data_bag_item('keeper', 'keeper_config').and_return({
      'config_json' => '{"token":"fake-token"}',
    })
    allow(::File).to receive(:exist?).and_call_original
    allow(::File).to receive(:exist?).with(real_python_path).and_return(true)
    allow(::File).to receive(:exist?).with(real_pip_path).and_return(true)
    allow(::File).to receive(:exist?).with(python_with_spaces).and_return(true)
    allow(::File).to receive(:exist?).with(pip_with_spaces).and_return(true)

    # Generic fallback for shell_out
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).and_return(shellout_not_found)
  end

  context 'with default Windows configuration' do
    before do
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python3').and_return(shellout_where_python3_multiple)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python').and_return(shellout_where_python3_real)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip3').and_return(shellout_where_pip3_real)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip').and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where choco').and_return(double('so', run_command: nil, error!: nil, stdout: '', exitstatus: 1))
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with(match(/--version/)).and_return(double('so', run_command: nil, error!: nil, stdout: 'Python 3.x', exitstatus: 0))

      # stub guards for pip show (both direct pip path and python -m pip fallback patterns)
      stub_command("\"#{real_pip_path}\" show keeper-secrets-manager-core").and_return(false)
      stub_command("\"#{real_pip_path}\" show keeper-secrets-manager-cli").and_return(false)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with("\"#{real_pip_path}\" show keeper-secrets-manager-core").and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with("\"#{real_pip_path}\" show keeper-secrets-manager-cli").and_return(shellout_not_found)
    end

    recipe do
      ksm_install 'keeper_secrets_manager' do
        action :install
      end
    end

    it 'creates Windows default directories' do
      expect(chef_run).to create_directory('C:\ProgramData\keeper_secrets_manager')
      expect(chef_run).to create_directory('C:\ProgramData\keeper_secrets_manager/config')
      expect(chef_run).to create_directory('C:\ProgramData\keeper_secrets_manager/scripts')
    end

    it 'filters out Windows Store Python stub' do
      expect(chef_run).to install_ksm_install('keeper_secrets_manager')
    end

    it 'uses python -m pip for pip upgrade on Windows' do
      expect(chef_run).to run_execute('upgrade_pip').with(
        command: match(/^"[^"]*python[^"]*" -m pip install --upgrade pip/)
      )
    end

    it 'quotes paths in pip commands' do
      expect(chef_run).to run_execute('install_keeper_sdk')
      execute_resource = chef_run.execute('install_keeper_sdk')
      expect(execute_resource.command).to match(/^"[^"]*pip[^"]*"/)
    end
  end

  context 'with Python in path with spaces' do
    before do
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python3').and_return(double('so', run_command: nil, error!: nil, stdout: "#{windows_store_stub}\n#{python_with_spaces}", exitstatus: 0))
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python').and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip3').and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip').and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where choco').and_return(double('so', run_command: nil, error!: nil, stdout: '', exitstatus: 1))
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with(match(/--version/)).and_return(double('so', run_command: nil, error!: nil, stdout: 'Python 3.x', exitstatus: 0))

      # stub python -m pip guards
      stub_command("\"#{python_with_spaces}\" -m pip show keeper-secrets-manager-core").and_return(false)
      stub_command("\"#{python_with_spaces}\" -m pip show keeper-secrets-manager-cli").and_return(false)
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
      expect(execute_resource.command).to match(/^"C:\\Program Files\\Python/)
    end

    it 'falls back to python -m pip when pip not found' do
      expect(chef_run).to run_execute('install_keeper_sdk')
      execute_resource = chef_run.execute('install_keeper_sdk')
      expect(execute_resource.command).to include('-m pip')
      expect(execute_resource.command).to match(/python[^"]*" -m pip install/)
    end
  end

  context 'when pip not in PATH but Python is available' do
    before do
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where python3').and_return(double('so', run_command: nil, error!: nil, stdout: real_python_path, exitstatus: 0))
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where pip3').and_return(shellout_not_found)
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('where choco').and_return(double('so', run_command: nil, error!: nil, stdout: '', exitstatus: 1))
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with(match(/--version/)).and_return(double('so', run_command: nil, error!: nil, stdout: 'Python 3.x', exitstatus: 0))

      stub_command("\"#{real_python_path}\" -m pip show keeper-secrets-manager-core").and_return(false)
      stub_command("\"#{real_python_path}\" -m pip show keeper-secrets-manager-cli").and_return(false)
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
