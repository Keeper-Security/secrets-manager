require 'spec_helper'
require 'tempfile'

RSpec.describe KeeperSecretsManager::Storage do
  describe KeeperSecretsManager::Storage::InMemoryStorage do
    let(:storage) { described_class.new }

    describe '#save_string and #get_string' do
      it 'stores and retrieves string values' do
        storage.save_string('key1', 'value1')
        expect(storage.get_string('key1')).to eq('value1')
      end

      it 'returns nil for non-existent keys' do
        expect(storage.get_string('nonexistent')).to be_nil
      end

      it 'overwrites existing values' do
        storage.save_string('key1', 'value1')
        storage.save_string('key1', 'value2')
        expect(storage.get_string('key1')).to eq('value2')
      end
    end

    describe '#save_bytes and #get_bytes' do
      it 'stores and retrieves binary data' do
        bytes = "\x00\x01\x02\x03".b
        storage.save_bytes('binary', bytes)
        retrieved = storage.get_bytes('binary')
        expect(retrieved).to eq(bytes)
        expect(retrieved.encoding).to eq(Encoding::ASCII_8BIT)
      end
    end

    describe '#delete' do
      it 'removes stored values' do
        storage.save_string('key1', 'value1')
        storage.delete('key1')
        expect(storage.get_string('key1')).to be_nil
      end
    end

    describe '#contains?' do
      it 'returns true for existing keys' do
        storage.save_string('key1', 'value1')
        expect(storage.contains?('key1')).to be true
      end

      it 'returns false for non-existent keys' do
        expect(storage.contains?('nonexistent')).to be false
      end
    end

    describe 'initialization from config' do
      it 'initializes from JSON string' do
        json = '{"key1": "value1", "key2": "value2"}'
        storage = described_class.new(json)
        expect(storage.get_string('key1')).to eq('value1')
        expect(storage.get_string('key2')).to eq('value2')
      end

      it 'initializes from hash' do
        hash = { 'key1' => 'value1', key2: 'value2' }
        storage = described_class.new(hash)
        expect(storage.get_string('key1')).to eq('value1')
        expect(storage.get_string('key2')).to eq('value2')
      end
    end
  end

  describe KeeperSecretsManager::Storage::FileStorage do
    let(:temp_file) { Tempfile.new(['keeper_config', '.json']) }
    let(:storage) { described_class.new(temp_file.path) }

    after do
      temp_file.close
      temp_file.unlink
    end

    describe 'persistence' do
      it 'persists data to file' do
        storage.save_string('key1', 'value1')
        
        # Create new instance to verify persistence
        new_storage = described_class.new(temp_file.path)
        expect(new_storage.get_string('key1')).to eq('value1')
      end

      it 'creates file with restrictive permissions' do
        storage.save_string('key1', 'value1')
        
        file_stat = File.stat(temp_file.path)
        # Check for 0600 permissions (owner read/write only)
        expect(file_stat.mode & 0777).to eq(0600)
      end

      it 'handles concurrent writes safely' do
        storage.save_string('key1', 'value1')
        storage.save_string('key2', 'value2')
        
        content = JSON.parse(File.read(temp_file.path))
        expect(content).to include('key1' => 'value1', 'key2' => 'value2')
      end
    end

    describe 'error handling' do
      it 'handles missing file gracefully' do
        non_existent = described_class.new('/tmp/nonexistent/keeper_config.json')
        expect(non_existent.get_string('key')).to be_nil
      end

      it 'raises error for invalid JSON' do
        File.write(temp_file.path, 'invalid json')
        expect { described_class.new(temp_file.path) }.to raise_error(KeeperSecretsManager::Error)
      end
    end
  end

  describe KeeperSecretsManager::Storage::EnvironmentStorage do
    let(:storage) { described_class.new('TEST_') }

    before do
      ENV['TEST_KEY1'] = 'value1'
      ENV['TEST_KEY2'] = 'value2'
    end

    after do
      ENV.delete('TEST_KEY1')
      ENV.delete('TEST_KEY2')
    end

    describe 'read operations' do
      it 'reads from environment variables' do
        expect(storage.get_string('key1')).to eq('value1')
        expect(storage.get_string('KEY1')).to eq('value1')
      end

      it 'returns nil for non-existent variables' do
        expect(storage.get_string('nonexistent')).to be_nil
      end
    end

    describe 'write operations' do
      it 'raises error on write attempts' do
        expect { storage.save_string('key', 'value') }.to raise_error(KeeperSecretsManager::Error)
      end

      it 'raises error on delete attempts' do
        expect { storage.delete('key') }.to raise_error(KeeperSecretsManager::Error)
      end
    end
  end

  describe KeeperSecretsManager::Storage::CachingStorage do
    let(:base_storage) { KeeperSecretsManager::Storage::InMemoryStorage.new }
    let(:storage) { described_class.new(base_storage, 2) } # 2 second TTL

    describe 'caching behavior' do
      it 'caches retrieved values' do
        base_storage.save_string('key1', 'value1')
        
        # First read - from base storage
        expect(storage.get_string('key1')).to eq('value1')
        
        # Change base storage
        base_storage.save_string('key1', 'value2')
        
        # Should still get cached value
        expect(storage.get_string('key1')).to eq('value1')
      end

      it 'respects TTL' do
        base_storage.save_string('key1', 'value1')
        storage.get_string('key1')
        
        # Change base storage
        base_storage.save_string('key1', 'value2')
        
        # Wait for cache to expire
        sleep 2.1
        
        # Should get new value
        expect(storage.get_string('key1')).to eq('value2')
      end

      it 'updates cache on write' do
        storage.save_string('key1', 'value1')
        expect(storage.get_string('key1')).to eq('value1')
        
        storage.save_string('key1', 'value2')
        expect(storage.get_string('key1')).to eq('value2')
      end

      it 'clears cache entries on delete' do
        storage.save_string('key1', 'value1')
        storage.get_string('key1') # Cache it
        
        storage.delete('key1')
        expect(storage.get_string('key1')).to be_nil
      end
    end

    describe '#clear_cache' do
      it 'removes all cached entries' do
        storage.save_string('key1', 'value1')
        storage.save_string('key2', 'value2')
        
        storage.clear_cache
        
        # Change base storage
        base_storage.save_string('key1', 'new_value1')
        base_storage.save_string('key2', 'new_value2')
        
        # Should get new values
        expect(storage.get_string('key1')).to eq('new_value1')
        expect(storage.get_string('key2')).to eq('new_value2')
      end
    end
  end
end