require 'spec_helper'
require_relative '../../../libraries/ksm_helpers'

RSpec.describe KeeperSecretsManagerCookbook::Helpers do
  # Chef mixes data_bag_item into the recipe/resource DSL. This stub class
  # gives the module a minimal host that plays that same role, so this file
  # tests the module in isolation instead of through a full ChefSpec converge.
  let(:test_class) do
    Class.new do
      include KeeperSecretsManagerCookbook::Helpers

      attr_accessor :data_bag_item_result, :data_bag_item_error

      def data_bag_item(*_args)
        raise data_bag_item_error if data_bag_item_error

        data_bag_item_result
      end
    end
  end
  let(:instance) { test_class.new }

  describe '#parse_secret_notation' do
    it 'defaults the output name to the last path segment when there is no ">"' do
      expect(instance.parse_secret_notation('UID/custom_field/Label1'))
        .to eq(['UID/custom_field/Label1', 'Label1', nil])
    end

    it 'strips the extension for a bare /file/ notation' do
      expect(instance.parse_secret_notation('UID/file/cert.pem'))
        .to eq(['UID/file/cert.pem', 'cert', nil])
    end

    it 'parses a plain output name after ">"' do
      expect(instance.parse_secret_notation('UID/custom_field/Label1 > OUT'))
        .to eq(['UID/custom_field/Label1', 'OUT', nil])
    end

    it 'parses an env: output spec' do
      expect(instance.parse_secret_notation('UID/custom_field/Token > env:TOKEN'))
        .to eq(['UID/custom_field/Token', 'TOKEN', :env])
    end

    it 'parses a file: output spec' do
      expect(instance.parse_secret_notation('UID/file/cert.pem > file:/tmp/cert.pem'))
        .to eq(['UID/file/cert.pem', '/tmp/cert.pem', :file])
    end

    it 'raises on more than one ">"' do
      expect { instance.parse_secret_notation('UID/a > b > c') }
        .to raise_error(ArgumentError, /Invalid secret structure/)
    end

    it 'raises on a bare notation with fewer than two path segments' do
      expect { instance.parse_secret_notation('no-slash-here') }
        .to raise_error(ArgumentError, /Invalid keeper notation/)
    end
  end

  describe '#load_keeper_config' do
    it 'prefers config_json from the data bag' do
      instance.data_bag_item_result = { 'config_json' => 'the-config', 'token' => 'unused' }
      expect(instance.load_keeper_config).to eq('the-config')
    end

    it 'falls back to the token field when config_json is absent' do
      instance.data_bag_item_result = { 'token' => 'the-token' }
      expect(instance.load_keeper_config).to eq('the-token')
    end

    it 'falls back to KEEPER_CONFIG when the data bag is missing' do
      instance.data_bag_item_error = Chef::Exceptions::InvalidDataBagPath
      allow(ENV).to receive(:[]).and_call_original
      allow(ENV).to receive(:[]).with('KEEPER_CONFIG').and_return('env-config')

      expect(instance.load_keeper_config).to eq('env-config')
    end

    it 'falls back to KEEPER_CONFIG when no encrypted_data_bag_secret is configured' do
      # Chef::EncryptedDataBagItem.load_secret raises plain ArgumentError for
      # this case - confirmed against Chef 19's actual source. There is no
      # dedicated "secret not found" exception class in Chef.
      instance.data_bag_item_error = ArgumentError
      allow(ENV).to receive(:[]).and_call_original
      allow(ENV).to receive(:[]).with('KEEPER_CONFIG').and_return('env-config')

      expect(instance.load_keeper_config).to eq('env-config')
    end
  end
end
