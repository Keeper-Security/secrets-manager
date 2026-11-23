# Chef InSpec test for recipe keeper_secrets_manager::install

# The Chef InSpec reference, with examples and extensive documentation, can be
# found at https://docs.chef.io/inspec/resources/

# test/integration/default/install_test.rb
# test/integration/default/install_test.rb
describe 'Keeper Secrets Manager Installation' do
  describe directory('/opt/keeper_secrets_manager') do
    it { should exist }
    it { should be_directory }
  end

  describe directory('/opt/keeper_secrets_manager/config') do
    it { should exist }
    it { should be_directory }
  end

  describe directory('/opt/keeper_secrets_manager/scripts') do
    it { should exist }
    it { should be_directory }
  end

  describe file('/opt/keeper_secrets_manager/scripts/ksm.py') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0755' }
  end

  describe command('python3 --version') do
    its('exit_status') { should eq 0 }
  end

  # Test that pip packages are installed
  describe command('pip3 show keeper-secrets-manager-core') do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/keeper-secrets-manager-core/) }
  end
end
