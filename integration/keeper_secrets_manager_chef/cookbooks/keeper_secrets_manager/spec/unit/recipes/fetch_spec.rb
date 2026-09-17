require 'spec_helper'

describe 'keeper_secrets_manager::fetch' do
  platform 'ubuntu'

  before do
    stub_data_bag_item('keeper', 'keeper_config').and_return('config_json' => 'fake-config')
  end

  it 'declares the ksm_fetch resource with the run action' do
    expect(chef_run).to run_ksm_fetch('fetch_secrets')
  end

  it 'logs success message' do
    expect(chef_run).to write_log('Keeper secrets fetched successfully!').with(level: :info)
  end
end
