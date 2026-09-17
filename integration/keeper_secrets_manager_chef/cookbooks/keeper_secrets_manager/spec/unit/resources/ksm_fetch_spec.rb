require 'spec_helper'
require 'chefspec'
require 'chefspec/solo_runner'
require 'keeper_secrets_manager'
require 'tmpdir'

describe 'ksm_fetch resource' do
  step_into :ksm_fetch
  platform 'ubuntu'
  # step_into + recipe do...end (ChefSpec's synthetic recipe) doesn't load
  # this cookbook's own attributes/default.rb the way a real chef-client run
  # or a named-recipe .converge() call does, so base_dir's lazy default
  # would otherwise evaluate against a nil node['keeper_secrets_manager'].
  default_attributes['keeper_secrets_manager']['base_dir'] = '/opt/keeper_secrets_manager'

  let(:secrets_manager_double) { instance_double(KeeperSecretsManager::Core::SecretsManager) }

  before do
    allow(::File).to receive(:exist?).and_call_original
    allow(::File).to receive(:exist?).with('/opt/keeper_secrets_manager/input.json').and_return(true)
    allow(::KeeperSecretsManager::Core::SecretsManager).to receive(:new).and_return(secrets_manager_double)
  end

  def stub_input_json(content)
    allow(::File).to receive(:read).and_call_original
    allow(::File).to receive(:read).with('/opt/keeper_secrets_manager/input.json').and_return(content.to_json)
  end

  context 'when the input file is missing' do
    before do
      allow(::File).to receive(:exist?).with('/opt/keeper_secrets_manager/input.json').and_return(false)
    end

    recipe do
      ksm_fetch 'missing_input' do
        action :run
      end
    end

    it 'raises a clear error instead of a bare LoadError/NoMethodError' do
      expect { chef_run }.to raise_error(RuntimeError, /Input file not found/)
    end
  end

  context 'with a direct-output (no prefix) secret' do
    before do
      stub_input_json(
        'authentication' => ['base64'],
        'secrets' => ['UID/field/password > DB_PASSWORD']
      )
      allow(secrets_manager_double).to receive(:get_notation).with('keeper://UID/field/password').and_return('s3cr3t')
      # SecretsManager.new is stubbed above; this just needs to be valid
      # JSON so the real InMemoryStorage.new constructor doesn't raise.
      stub_data_bag_item('keeper', 'keeper_config').and_return('config_json' => '{}')
    end

    recipe do
      ksm_fetch 'direct_output' do
        action :run
      end
    end

    it 'stores the value in node.run_state, never on disk' do
      chef_run
      expect(chef_run.node.run_state['keeper_secrets']['DB_PASSWORD']).to eq('s3cr3t')
    end
  end

  context 'with an env: secret' do
    before do
      stub_input_json(
        'authentication' => ['base64'],
        'secrets' => ['UID/custom_field/Token > env:API_TOKEN']
      )
      allow(secrets_manager_double).to receive(:get_notation).with('keeper://UID/custom_field/Token').and_return('tok-123')
      stub_data_bag_item('keeper', 'keeper_config').and_return('config_json' => '{}')
    end

    recipe do
      ksm_fetch 'env_output' do
        action :run
      end
    end

    after { ENV.delete('API_TOKEN') }

    it 'sets the real process ENV variable' do
      chef_run
      expect(ENV.fetch('API_TOKEN', nil)).to eq('tok-123')
    end
  end

  context 'with a file: secret' do
    let(:target_path) { "#{Dir.tmpdir}/ksm_fetch_spec_cert_#{Process.pid}.pem" }

    before do
      stub_input_json(
        'authentication' => ['base64'],
        'secrets' => ["UID/file/cert.pem > file:#{target_path}"]
      )
      allow(secrets_manager_double).to receive(:get_notation).with('keeper://UID/file/cert.pem').and_return('CERT-CONTENT')
      stub_data_bag_item('keeper', 'keeper_config').and_return('config_json' => '{}')
    end

    after { ::File.delete(target_path) if ::File.exist?(target_path) }

    recipe do
      ksm_fetch 'file_output' do
        action :run
      end
    end

    it 'writes the file and restricts it to 0600' do
      chef_run
      expect(::File.read(target_path)).to eq('CERT-CONTENT')
      expect(::File.stat(target_path).mode & 0o777).to eq(0o600)
    end

    context 'when a symlink is already sitting at the destination' do
      let(:attacker_owned_file) { "#{Dir.tmpdir}/ksm_fetch_spec_attacker_#{Process.pid}.txt" }

      before do
        ::File.write(attacker_owned_file, 'attacker-original-content')
        ::File.symlink(attacker_owned_file, target_path)
      end

      after { ::File.delete(attacker_owned_file) if ::File.exist?(attacker_owned_file) }

      it 'replaces the symlink instead of writing through it' do
        chef_run
        expect(::File.symlink?(target_path)).to be false
        expect(::File.read(target_path)).to eq('CERT-CONTENT')
        expect(::File.read(attacker_owned_file)).to eq('attacker-original-content')
      end
    end
  end

  context 'with the base64 authentication method' do
    before do
      stub_input_json('authentication' => ['base64'], 'secrets' => [])
      stub_data_bag_item('keeper', 'keeper_config').and_return('config_json' => 'fake-base64-config')
    end

    recipe do
      ksm_fetch 'base64_auth' do
        action :run
      end
    end

    it 'builds an InMemoryStorage from load_keeper_config, never from input.json' do
      expect(::KeeperSecretsManager::Storage::InMemoryStorage).to receive(:new)
        .with('fake-base64-config')
        .and_return(instance_double(::KeeperSecretsManager::Storage::InMemoryStorage))
      chef_run
    end
  end

  context 'with the base64 authentication method and no config anywhere' do
    before do
      stub_input_json('authentication' => ['base64'], 'secrets' => [])
      stub_data_bag_item('keeper', 'keeper_config').and_raise(Chef::Exceptions::InvalidDataBagPath)
      allow(ENV).to receive(:[]).and_call_original
      allow(ENV).to receive(:[]).with('KEEPER_CONFIG').and_return(nil)
    end

    recipe do
      ksm_fetch 'base64_no_config' do
        action :run
      end
    end

    it 'raises instead of silently constructing an unbound SecretsManager' do
      expect { chef_run }.to raise_error(/No Keeper config found/)
    end
  end

  context 'with the token authentication method' do
    before do
      stub_input_json('authentication' => %w(token ONE-TIME-TOKEN), 'secrets' => [])
    end

    recipe do
      ksm_fetch 'token_auth' do
        action :run
      end
    end

    it 'uses the literal token from input.json, not load_keeper_config' do
      expect(::KeeperSecretsManager::Storage::FileStorage).to receive(:new)
        .with('/opt/keeper_secrets_manager/config/keeper_config.json')
        .and_return(instance_double(::KeeperSecretsManager::Storage::FileStorage))
      expect(::KeeperSecretsManager::Core::SecretsManager).to receive(:new)
        .with(hash_including(token: 'ONE-TIME-TOKEN')).and_return(secrets_manager_double)
      chef_run
    end
  end

  context 'with the json authentication method' do
    before do
      stub_input_json('authentication' => ['json', '/etc/keeper/my-config.json'], 'secrets' => [])
      # A KEEPER_CONFIG env var is set, simulating the exact scenario that
      # silently hijacked the old Python script's "json" method - this test
      # fails if that regression comes back.
      allow(ENV).to receive(:[]).and_call_original
      allow(ENV).to receive(:[]).with('KEEPER_CONFIG').and_return('should-never-be-used')
    end

    recipe do
      ksm_fetch 'json_auth' do
        action :run
      end
    end

    it 'uses the literal path from input.json, unconditionally, ignoring KEEPER_CONFIG' do
      expect(::KeeperSecretsManager::Storage::FileStorage).to receive(:new)
        .with('/etc/keeper/my-config.json')
        .and_return(instance_double(::KeeperSecretsManager::Storage::FileStorage))
      chef_run
    end
  end

  context 'with an unsupported authentication method' do
    before do
      stub_input_json('authentication' => ['carrier-pigeon'], 'secrets' => [])
    end

    recipe do
      ksm_fetch 'bad_auth' do
        action :run
      end
    end

    it 'raises ArgumentError naming the unsupported method' do
      expect { chef_run }.to raise_error(ArgumentError, /Unsupported authentication method/)
    end
  end
end
