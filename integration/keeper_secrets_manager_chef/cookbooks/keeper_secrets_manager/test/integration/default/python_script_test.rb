# test/integration/default/python_script_test.rb
describe 'Python script functionality' do
  describe file('/opt/keeper_secrets_manager/scripts/ksm.py') do
    it { should exist }
    it { should be_executable }
    its('mode') { should cmp '0755' }
  end

  describe command('python3 /opt/keeper_secrets_manager/scripts/ksm.py --help') do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/Keeper Secrets CLI/) }
  end

  # Test with mock input file
  describe 'Python script with test input' do
    let(:test_input) { '/tmp/test_input.json' }

    before do
      # Create test input file
      test_config = {
        'authentication' => %w(token test-token),
        'secrets' => ['test/secret/path'],
        'folders' => {},
      }

      file test_input do
        content test_config.to_json
        mode '0644'
      end
    end

    # NOTE: This would need actual Keeper credentials to work
    # describe command("python3 /opt/keeper_secrets_manager/scripts/ksm.py --input #{test_input}") do
    #   its('exit_status') { should eq 0 }
    # end
  end
end
