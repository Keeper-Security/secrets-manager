require 'spec_helper'

describe 'keeper_secret_manager_puppet::lookup_env_value' do
  it { is_expected.not_to eq(nil) }

  context 'input validation' do
    it 'returns nil for invalid ENV: prefix' do
      is_expected.to run.with_params('KEEPER_CONFIG').and_return(nil)
    end

    it 'returns nil for empty variable name after ENV: prefix' do
      is_expected.to run.with_params('ENV:').and_return(nil)
    end

    it 'returns nil for whitespace-only variable name after ENV: prefix' do
      is_expected.to run.with_params('ENV:   ').and_return(nil)
    end
  end

  context 'Method 1: Current process environment' do
    it 'returns environment variable value when set in current process' do
      stub_const('ENV', ENV.to_hash.merge('KEEPER_CONFIG' => 'env_value'))
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return('env_value')
    end

    it 'returns nil when environment variable is not set in current process' do
      stub_const('ENV', ENV.to_hash.reject { |k, _| k == 'KEEPER_CONFIG' })
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return(nil)
    end

    it 'returns nil when environment variable is empty string' do
      stub_const('ENV', ENV.to_hash.merge('KEEPER_CONFIG' => ''))
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return(nil)
    end

    it 'returns nil when environment variable is whitespace only' do
      stub_const('ENV', ENV.to_hash.merge('KEEPER_CONFIG' => '   '))
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return(nil)
    end

    it 'strips whitespace from environment variable value' do
      stub_const('ENV', ENV.to_hash.merge('KEEPER_CONFIG' => '  env_value  '))
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return('env_value')
    end
  end

  context 'Method 3: Puppet-specific files' do
    before(:each) do
      stub_const('ENV', ENV.to_hash.reject { |k, _| k == 'KEEPER_CONFIG' })
      allow(RbConfig::CONFIG).to receive(:[]).with('host_os').and_return('linux')
      allow(File).to receive(:exist?).and_return(false)
      allow(Dir).to receive(:exist?).and_return(false)
    end

    it 'finds environment variable in keeper_env.sh' do
      allow(File).to receive(:exist?).with('/opt/keeper_secret_manager/keeper_env.sh').and_return(true)
      allow(File).to receive(:readlines).with('/opt/keeper_secret_manager/keeper_env.sh').and_return(['export KEEPER_CONFIG=keeper_env_value'])
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return('keeper_env_value')
    end

    it 'finds environment variable in keeper_env_auth_value.sh' do
      allow(File).to receive(:exist?).with('/opt/keeper_secret_manager/keeper_env_auth_value.sh').and_return(true)
      allow(File).to receive(:readlines).with('/opt/keeper_secret_manager/keeper_env_auth_value.sh').and_return(['export KEEPER_CONFIG=keeper_auth_value'])
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return('keeper_auth_value')
    end

    it 'finds environment variable in puppet environment.conf' do
      allow(File).to receive(:exist?).with('/etc/puppetlabs/puppet/environment.conf').and_return(true)
      allow(File).to receive(:readlines).with('/etc/puppetlabs/puppet/environment.conf').and_return(['export KEEPER_CONFIG=puppet_env_value'])
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return('puppet_env_value')
    end

    it 'handles file read errors in puppet environment files' do
      allow(File).to receive(:exist?).with('/opt/keeper_secret_manager/keeper_env.sh').and_return(true)
      allow(File).to receive(:readlines).with('/opt/keeper_secret_manager/keeper_env.sh').and_raise(StandardError.new('File read error'))
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return(nil)
    end

    it 'skips empty values from puppet environment files' do
      allow(File).to receive(:exist?).with('/opt/keeper_secret_manager/keeper_env.sh').and_return(true)
      allow(File).to receive(:readlines).with('/opt/keeper_secret_manager/keeper_env.sh').and_return(['export KEEPER_CONFIG='])
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return(nil)
    end
  end

  context 'integration scenarios' do
    it 'returns first found value when multiple sources have the variable' do
      stub_const('ENV', ENV.to_hash.merge('KEEPER_CONFIG' => 'process_value'))
      allow(File).to receive(:exist?).and_return(true)
      allow(File).to receive(:readlines).and_return(['export KEEPER_CONFIG=file_value'])
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return('process_value')
    end

    it 'returns nil when variable is not found in any source' do
      stub_const('ENV', ENV.to_hash.reject { |k, _| k == 'KEEPER_CONFIG' })
      allow(RbConfig::CONFIG).to receive(:[]).with('host_os').and_return('linux')
      allow(File).to receive(:exist?).and_return(false)
      allow(Dir).to receive(:exist?).and_return(false)
      is_expected.to run.with_params('ENV:KEEPER_CONFIG').and_return(nil)
    end
  end
end
