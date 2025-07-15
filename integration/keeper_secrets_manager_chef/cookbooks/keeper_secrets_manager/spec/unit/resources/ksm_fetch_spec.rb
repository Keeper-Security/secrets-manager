require 'spec_helper'

describe 'ksm_fetch resource' do
  step_into :ksm_fetch
  platform 'ubuntu'

  let(:shellout_double_python3) do
    double('shell_out', run_command: nil, error!: nil, stdout: '/usr/bin/python3', exitstatus: 0)
  end

  before do
    allow(::File).to receive(:exist?).and_call_original
    allow(::File).to receive(:exist?).with('/custom/input.json').and_return(true)

    # stub_data_bag_item('keeper', 'keeper_config').and_return({
    #   'config_json' => '{"token":"test-token"}'
    # })

    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which python3').and_return(shellout_double_python3)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which python').and_return(shellout_double_python3)
    stub_command('which python3').and_return(true)
  end

  context 'with default configuration' do
    before do
      stub_data_bag_item('keeper', 'keeper_config').and_return({
        'config_json' => '{"token":"test-token"}',
      })
    end

    recipe do
      ksm_fetch 'run_default' do
        action :run
      end
    end

    it 'deploys the keeper secret script' do
      expect(chef_run).to create_cookbook_file('/opt/keeper_secrets_manager/ksm.py').with(
        source: 'ksm.py',
        mode: '0755'
      )
    end

    it 'executes the keeper secret script with default path' do
      expect(chef_run).to run_execute('keeper_fetch_run_default').with(
        command: 'python3 /opt/keeper_secrets_manager/ksm.py',
        timeout: 300,
        live_stream: true,
        environment: hash_including('KEEPER_CONFIG' => '{"token":"test-token"}')
      )
    end
  end

  context 'with input_path set' do
    before do
      stub_data_bag_item('keeper', 'keeper_config').and_return({
        'config_json' => '{"token":"test-token"}',
      })
    end
    recipe do
      ksm_fetch 'run_with_input' do
        input_path '/custom/input.json'
        action :run
      end
    end

    it 'executes the keeper script with the input path' do
      expect(chef_run).to run_execute('keeper_fetch_run_with_input').with(
        command: 'python3 /opt/keeper_secrets_manager/ksm.py --input /custom/input.json',
        environment: hash_including('KEEPER_CONFIG' => '{"token":"test-token"}')
      )
    end
  end

  context 'when input_path is specified but file is missing' do
    before do
      allow(::File).to receive(:exist?).with('/missing/input.json').and_return(false)
      stub_data_bag_item('keeper', 'keeper_config').and_return({
        'config_json' => '{"token":"test-token"}',
      })
    end

    recipe do
      ksm_fetch 'run_missing_input' do
        input_path '/missing/input.json'
        action :run
      end
    end

    it 'raises a file not found error' do
      expect { chef_run }.to raise_error(RuntimeError, /Input file not found/)
    end
  end

  context 'when python3 and python are not found' do
    before do
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which python3')
                                                                  .and_return(double('shell_out', run_command: nil, error!: nil, stdout: '', exitstatus: 1))
      allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which python')
                                                                  .and_return(double('shell_out', run_command: nil, error!: nil, stdout: '', exitstatus: 1))
      stub_data_bag_item('keeper', 'keeper_config').and_return({
        'config_json' => '{"token":"test-token"}',
      })
    end

    recipe do
      ksm_fetch 'fallback_python' do
        action :run
      end
    end

    it 'falls back to python3 in command' do
      expect(chef_run).to run_execute('keeper_fetch_fallback_python').with(
        command: 'python3 /opt/keeper_secrets_manager/ksm.py'
      )
    end
  end

  context 'with custom timeout' do
    before do
      stub_data_bag_item('keeper', 'keeper_config').and_return({
        'config_json' => '{"token":"test-token"}',
      })
    end
    recipe do
      ksm_fetch 'with_timeout' do
        timeout 120
        action :run
      end
    end

    it 'uses custom timeout in execute' do
      expect(chef_run).to run_execute('keeper_fetch_with_timeout').with(
        timeout: 120
      )
    end
  end

  context 'with python' do
    before do
      stub_data_bag_item('keeper', 'keeper_config').and_return({
        'config_json' => '{"token":"test-token"}',
      })
    end
    recipe do
      ksm_fetch 'test_script' do
        action :run
      end
    end

    it 'deploys the Python script with correct permissions' do
      expect(chef_run).to create_cookbook_file('/opt/keeper_secrets_manager/ksm.py').with(
        source: 'ksm.py',
        mode: '0755'
      )
    end
  end

  context 'when encrypted data bag is missing' do
    before do
      # This is how ChefSpec expects data_bag_item to be stubbed if you want it to raise
      stub_data_bag_item('keeper', 'keeper_config').and_raise(Chef::Exceptions::InvalidDataBagPath)

      # Stub ENV fallback
      allow(ENV).to receive(:[]).and_call_original
      allow(ENV).to receive(:[]).with('KEEPER_CONFIG').and_return('{"token":"env-token"}')
    end

    recipe do
      ksm_fetch 'fallback_to_env' do
        action :run
      end
    end

    it 'uses fallback env variable for config' do
      expect(chef_run).to run_execute('keeper_fetch_fallback_to_env').with(
        environment: hash_including('KEEPER_CONFIG' => '{"token":"env-token"}')
      )
    end
  end
end 