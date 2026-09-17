require 'spec_helper'

describe 'keeper_secrets_manager::install' do
  before do
    stub_data_bag_item('keeper', 'keeper_config').and_return('config_json' => 'fake-config')
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

  it 'installs the pinned gem version' do
    expect(chef_run).to install_chef_gem('keeper_secrets_manager').with(version: '17.2.1')
  end

  it 'creates the base directory' do
    expect(chef_run).to create_directory('/opt/keeper_secrets_manager')
  end

  it 'creates the config directory' do
    expect(chef_run).to create_directory('/opt/keeper_secrets_manager/config')
  end

  it 'creates the Keeper config file' do
    expect(chef_run).to create_file('/opt/keeper_secrets_manager/config/keeper_config.json').with(
      content: 'fake-config',
      mode: '0600',
      sensitive: true
    )
  end

  it 'logs installation complete' do
    expect(chef_run).to write_log('Keeper Secrets Manager installation complete!').with(level: :info)
  end
end
