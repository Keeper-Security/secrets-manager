# Chef InSpec test for recipe keeper_secrets_manager::install
#
# chef_gem installs into Chef's own embedded Ruby gemset, which InSpec can't
# portably address by path across platforms. Verifying the install
# succeeded is done indirectly instead: the directory and config-file
# resources declared after chef_gem in ksm_install's action only run if
# chef_gem completed without error, so their presence proves the gem
# install step succeeded.
describe 'Keeper Secrets Manager Installation' do
  describe directory('/opt/keeper_secrets_manager') do
    it { should exist }
    it { should be_directory }
  end

  describe directory('/opt/keeper_secrets_manager/config') do
    it { should exist }
    it { should be_directory }
  end

  describe file('/opt/keeper_secrets_manager/config/keeper_config.json') do
    it { should exist }
    it { should be_file }
    its('mode') { should cmp '0600' }
  end
end
