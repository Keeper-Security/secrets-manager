require 'chefspec'

RSpec.configure do |config|
  config.before(:each) do
    # Stub any file exist check to default to false unless specifically expected
    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:read).and_call_original

    # NOTE: Chef automatically handles encrypted_data_bag_secret path on all platforms
    # No need to stub the hardcoded path since we removed it from the code

    # Stub encrypted data bag load to return a predictable fake
    allow(Chef::EncryptedDataBagItem).to receive(:load_secret).and_return('fake-secret')
    allow(Chef::EncryptedDataBagItem).to receive(:load).and_return({ 'token' => 'fake-token' })
  end
end
