require 'spec_helper'
require 'chefspec'
require 'chefspec/solo_runner'

describe 'keeper_secrets_manager::install (ksm_install resource)' do
  let(:runner) { ChefSpec::SoloRunner.new(platform: 'ubuntu', version: '22.04') }
  let(:chef_run) { runner.converge('keeper_secrets_manager::install') }

  before do
    stub_data_bag_item('keeper', 'keeper_config').and_return('config_json' => 'fake-config')
  end

  it 'converges the install recipe and declares the ksm_install resource' do
    expect { chef_run }.to_not raise_error
    expect(chef_run).to install_ksm_install('keeper_secrets_manager')
  end
end

describe 'ksm_install resource' do
  step_into :ksm_install
  platform 'ubuntu'
  # step_into + recipe do...end (ChefSpec's synthetic recipe) doesn't load
  # this cookbook's own attributes/default.rb the way a real chef-client run
  # or a named-recipe .converge() call does, so base_dir's lazy default
  # would otherwise evaluate against a nil node['keeper_secrets_manager'].
  default_attributes['keeper_secrets_manager']['base_dir'] = '/opt/keeper_secrets_manager'

  context 'with default configuration' do
    before do
      stub_data_bag_item('keeper', 'keeper_config').and_return('config_json' => 'fake-config')
    end

    recipe do
      ksm_install 'keeper_secrets_manager' do
        action :install
      end
    end

    it 'installs the pinned gem version' do
      expect(chef_run).to install_chef_gem('keeper_secrets_manager').with(version: '17.2.1')
    end

    it 'creates the base and config directories' do
      expect(chef_run).to create_directory('/opt/keeper_secrets_manager')
      expect(chef_run).to create_directory('/opt/keeper_secrets_manager/config')
    end

    it 'creates the keeper config file from the encrypted data bag' do
      expect(chef_run).to create_file('/opt/keeper_secrets_manager/config/keeper_config.json').with(
        content: 'fake-config',
        mode: '0600',
        sensitive: true
      )
    end
  end

  context 'with a custom sdk_version' do
    before do
      stub_data_bag_item('keeper', 'keeper_config').and_return('config_json' => 'fake-config')
    end

    recipe do
      ksm_install 'pinned' do
        sdk_version '17.1.0'
        action :install
      end
    end

    it 'installs the requested gem version instead of the default' do
      expect(chef_run).to install_chef_gem('keeper_secrets_manager').with(version: '17.1.0')
    end
  end

  context 'with a custom base_dir' do
    before do
      stub_data_bag_item('keeper', 'keeper_config').and_return('config_json' => 'fake-config')
    end

    recipe do
      ksm_install 'custom_path' do
        base_dir '/custom/path'
        action :install
      end
    end

    it 'creates directories at the custom location, not the default' do
      expect(chef_run).to create_directory('/custom/path')
      expect(chef_run).to create_directory('/custom/path/config')
    end
  end

  context 'when no Keeper config is available anywhere' do
    before do
      stub_data_bag_item('keeper', 'keeper_config').and_raise(Chef::Exceptions::InvalidDataBagPath)
      allow(ENV).to receive(:[]).and_call_original
      allow(ENV).to receive(:[]).with('KEEPER_CONFIG').and_return(nil)
    end

    recipe do
      ksm_install 'no_config' do
        action :install
      end
    end

    it 'warns and skips the config file instead of raising' do
      expect { chef_run }.to_not raise_error
      expect(chef_run).to_not create_file('/opt/keeper_secrets_manager/config/keeper_config.json')
    end
  end

  context 'action :remove' do
    recipe do
      ksm_install 'removed' do
        action :remove
      end
    end

    it 'removes the gem and deletes the base directory' do
      expect(chef_run).to remove_chef_gem('keeper_secrets_manager')
      expect(chef_run).to delete_directory('/opt/keeper_secrets_manager')
    end
  end

  context 'action :upgrade' do
    recipe do
      ksm_install 'upgraded' do
        action :upgrade
      end
    end

    it 'upgrades the gem to the pinned version' do
      expect(chef_run).to upgrade_chef_gem('keeper_secrets_manager').with(version: '17.2.1')
    end
  end
end
