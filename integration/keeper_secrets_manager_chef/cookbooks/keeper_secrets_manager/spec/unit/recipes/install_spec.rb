require 'spec_helper'

describe 'keeper_secrets_manager::install' do
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

    # Also stub pip show check
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('/usr/bin/pip3 show keeper-secrets-manager-core').and_return(shellout_double_not_found)
    stub_command('/usr/bin/pip3 show keeper-secrets-manager-core').and_return(false)
  end

  let(:chef_run) do
    ChefSpec::SoloRunner.new(
      platform: 'ubuntu',
      version: '22.04',
      step_into: ['ksm_install']
    ).converge(described_recipe)
  end

  it 'runs the ksm_install resource' do
    expect(chef_run).to install_ksm_install('keeper_secrets_manager')
  end

  it 'creates the base directory' do
    expect(chef_run).to create_directory('/opt/keeper_secrets_manager')
  end

  it 'executes pip upgrade' do
    expect(chef_run).to run_execute('upgrade_pip').with(
      command: 'sudo /usr/bin/pip3 install --upgrade pip'
    )
  end

  it 'installs the Keeper SDK package' do
    expect(chef_run).to run_execute('install_keeper_sdk').with(
      command: 'sudo /usr/bin/pip3 install --upgrade keeper-secrets-manager-core'
    )
  end

  it 'verifies the Keeper SDK install' do
    expect(chef_run).to run_execute('verify_sdk').with(
      command: '/usr/bin/python3 -c "import keeper_secrets_manager_core; print(\'SDK OK\')"'
    )
  end

  it 'creates the config directory' do
    expect(chef_run).to create_directory('/opt/keeper_secrets_manager/config')
  end

  it 'creates the scripts directory' do
    expect(chef_run).to create_directory('/opt/keeper_secrets_manager/scripts')
  end

  it 'installs the ksm.py script' do
    expect(chef_run).to create_cookbook_file('/opt/keeper_secrets_manager/scripts/ksm.py')
  end

  it 'creates the Keeper config file' do
    expect(chef_run).to create_file('/opt/keeper_secrets_manager/config/keeper_config.json').with(
      content: '{"token":"fake-token"}',
      mode: '0600',
      sensitive: true
    )
  end
end
