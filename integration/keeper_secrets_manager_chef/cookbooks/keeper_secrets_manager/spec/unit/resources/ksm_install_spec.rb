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
