require 'spec_helper'
require 'json'

describe 'keeper_secret_manager_puppet::lookup' do
  let(:default_env_path) { '/opt/keeper_secret_manager/keeper_env.sh' }
  let(:default_input_path) { '/opt/keeper_secret_manager/input.json' }
  let(:default_script_path) { '/opt/keeper_secret_manager/ksm.py' }
  let(:valid_auth_config) { { 'authentication' => [['token', 'abc123']], 'secrets' => ['record.uid.field'] } }

  before(:each) do
    # Stub Facter to handle any value call
    allow(Facter).to receive(:value).and_return('Debian')

    # Stub all file checks - be more specific about what exists
    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:exist?).with(default_script_path).and_return(true)
    allow(File).to receive(:exist?).with(default_input_path).and_return(true)
    allow(File).to receive(:exist?).with(default_env_path).and_return(false)

    # Stub reading input.json - handle any file read
    allow(File).to receive(:read).and_call_original
    allow(File).to receive(:read).with(default_input_path).and_return({ 'authentication' => ['token', 'abc123'] }.to_json)

    # Stub Open3 execution - use instance_double for Process::Status
    process_status = instance_double(Process::Status, success?: true)
    allow(Open3).to receive(:capture3).and_return(['{"result": "ok"}', '', process_status])

    # Stub python3 executable
    allow(Puppet::Util).to receive(:which).with('python3').and_return('/usr/bin/python3')
  end

  context 'with no parameters' do
    it 'calls the script using the default input.json' do
      is_expected.to run.with_params.and_return({ 'result' => 'ok' })
    end
  end

  context 'with a single secret string' do
    it 'calls the script with one secret' do
      process_status = instance_double(Process::Status, success?: true)
      allow(Open3).to receive(:capture3).with(any_args).and_return(['{"result": "ok"}', '', process_status])

      is_expected.to run.with_params('record.uid.field').and_return({ 'result' => 'ok' })
    end
  end

  context 'with multiple secrets' do
    it 'calls the script with multiple secrets' do
      is_expected.to run.with_params(['record.uid1.field', 'record.uid2.field']).and_return({ 'result' => 'ok' })
    end

    it 'raises error for empty array' do
      is_expected.to run.with_params([]).and_raise_error(ArgumentError, %r{at least one string})
    end
  end

  context 'when input.json is missing' do
    it 'raises Puppet::Error' do
      allow(File).to receive(:exist?).with(default_input_path).and_return(false)

      is_expected.to run.with_params.and_raise_error(Puppet::Error, %r{Config file not found})
    end
  end

  context 'when input.json has invalid JSON' do
    before(:each) do
      # Override the default stubs for this context
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with(default_script_path).and_return(true)
      allow(File).to receive(:exist?).with(default_input_path).and_return(true)
      allow(File).to receive(:exist?).with('/opt/keeper_secret_manager/keeper_config.json').and_return(true)
      allow(File).to receive(:read).and_call_original
      allow(File).to receive(:read).with(default_input_path).and_return('invalid_json')
      # Force script execution to fail
      failed_status = instance_double(Process::Status, success?: false, exitstatus: 1)
      allow(Open3).to receive(:capture3).and_return(['', '', failed_status])
    end

    it 'raises Puppet::Error' do
      is_expected.to run.with_params('record.uid.field').and_raise_error(Puppet::Error, %r{Invalid JSON})
    end
  end

  context 'when authentication config is invalid' do
    before(:each) do
      # Override the default stubs for this context
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with(default_script_path).and_return(true)
      allow(File).to receive(:exist?).with(default_input_path).and_return(true)
      allow(File).to receive(:exist?).with('/opt/keeper_secret_manager/keeper_config.json').and_return(true)
      allow(File).to receive(:read).and_call_original
      bad_auth_config = { 'authentication' => 'string_not_array' }.to_json
      allow(File).to receive(:read).with(default_input_path).and_return(bad_auth_config)
      # Force script execution to fail
      failed_status = instance_double(Process::Status, success?: false, exitstatus: 1)
      allow(Open3).to receive(:capture3).and_return(['', '', failed_status])
    end

    it 'raises Puppet::Error' do
      is_expected.to run.with_params('record.uid.field').and_raise_error(Puppet::Error, %r{must be an array})
    end
  end

  context 'when script execution fails' do
    it 'logs error and returns message' do
      failed_status = instance_double(Process::Status, success?: false, exitstatus: 1)
      success_status = instance_double(Process::Status, success?: true)
      allow(Open3).to receive(:capture3).with(any_args).and_return(['', '[ERROR] failure', failed_status])
      allow(Open3).to receive(:capture3).with('/usr/bin/python3', '-c', 'import keeper_secrets_manager_core').and_return(['', '', success_status])
      expect(Puppet).to receive(:err).with('[ERROR] failure')
      expect(Puppet).to receive(:err).with(%r{Keeper lookup failed with exit code 1})

      is_expected.to run.with_params('record.uid.field').and_return(%r{Keeper lookup failed})
    end
  end
end
