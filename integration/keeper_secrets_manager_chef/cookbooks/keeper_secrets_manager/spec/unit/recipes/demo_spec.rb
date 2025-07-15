require 'spec_helper'

describe 'keeper_secrets_manager::demo' do
  platform 'ubuntu'

  let(:shellout_double_python3) do
    double('shell_out', run_command: nil, error!: nil, stdout: '/usr/bin/python3', exitstatus: 0)
  end

  before do
    # Stub python detection
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which python3').and_return(shellout_double_python3)
    allow_any_instance_of(Chef::Provider).to receive(:shell_out).with('which python').and_return(shellout_double_python3)
    stub_command('which python3').and_return(true)

    # Stub data bag
    stub_data_bag_item('keeper', 'keeper_config').and_return({
      'config_json' => '{"token":"test-token"}',
    })
  end

  it 'runs the ksm_fetch resource' do
    expect(chef_run).to run_ksm_fetch('fetch_secrets')
  end

  it 'logs success message' do
    expect(chef_run).to write_log('Keeper secrets fetched successfully !').with(level: :info)
  end
end
