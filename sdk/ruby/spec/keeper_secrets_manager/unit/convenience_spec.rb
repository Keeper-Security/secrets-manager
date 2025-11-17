require 'spec_helper'
require 'tempfile'

RSpec.describe 'Convenience Methods' do
  let(:storage) do
    KeeperSecretsManager::Storage::InMemoryStorage.new({
      'hostname' => 'keepersecurity.com',
      'clientId' => Base64.strict_encode64('test-client'),
      'appKey' => Base64.strict_encode64(SecureRandom.random_bytes(32))
    })
  end

  describe '#upload_file_from_path' do
    it 'reads file from disk and uploads it' do
      # Create temporary file
      temp_file = Tempfile.new(['test', '.txt'])
      temp_file.write('test file content')
      temp_file.close

      begin
        sm = KeeperSecretsManager.new(config: storage)

        # Mock the upload_file method to verify it's called correctly
        expect(sm).to receive(:upload_file).with(
          'test-record-uid',
          'test file content',
          File.basename(temp_file.path),
          File.basename(temp_file.path)
        ).and_return('mock-file-uid')

        result = sm.upload_file_from_path('test-record-uid', temp_file.path)

        expect(result).to eq('mock-file-uid')
      ensure
        temp_file.unlink
      end
    end

    it 'uses custom file_title when provided' do
      temp_file = Tempfile.new(['test', '.pdf'])
      temp_file.write('PDF content')
      temp_file.close

      begin
        sm = KeeperSecretsManager.new(config: storage)

        expect(sm).to receive(:upload_file).with(
          'test-record-uid',
          'PDF content',
          File.basename(temp_file.path),
          'Custom Title'
        ).and_return('mock-file-uid')

        result = sm.upload_file_from_path(
          'test-record-uid',
          temp_file.path,
          file_title: 'Custom Title'
        )

        expect(result).to eq('mock-file-uid')
      ensure
        temp_file.unlink
      end
    end

    it 'raises error if file does not exist' do
      sm = KeeperSecretsManager.new(config: storage)

      expect {
        sm.upload_file_from_path('test-record-uid', '/nonexistent/file.txt')
      }.to raise_error(ArgumentError, /File not found/)
    end

    it 'raises error if path is a directory' do
      sm = KeeperSecretsManager.new(config: storage)

      expect {
        sm.upload_file_from_path('test-record-uid', Dir.tmpdir)
      }.to raise_error(ArgumentError, /Path is a directory/)
    end

    it 'handles binary files correctly' do
      temp_file = Tempfile.new(['binary', '.bin'], binmode: true)
      binary_data = [0xFF, 0xD8, 0xFF, 0xE0].pack('C*')
      temp_file.write(binary_data)
      temp_file.close

      begin
        sm = KeeperSecretsManager.new(config: storage)

        expect(sm).to receive(:upload_file).with(
          'test-record-uid',
          binary_data,
          File.basename(temp_file.path),
          File.basename(temp_file.path)
        ).and_return('mock-file-uid')

        result = sm.upload_file_from_path('test-record-uid', temp_file.path)

        expect(result).to eq('mock-file-uid')
      ensure
        temp_file.unlink
      end
    end
  end

  describe '#try_get_notation' do
    it 'returns value when notation is valid' do
      sm = KeeperSecretsManager.new(config: storage)

      # Mock the parser to return a value
      allow_any_instance_of(KeeperSecretsManager::Notation::Parser).to receive(:parse)
        .and_return('secret-value')

      result = sm.try_get_notation('keeper://test-uid/field/password')

      expect(result).to eq('secret-value')
    end

    it 'returns empty array when notation is invalid' do
      sm = KeeperSecretsManager.new(config: storage)

      # Mock the parser to raise NotationError
      allow_any_instance_of(KeeperSecretsManager::Notation::Parser).to receive(:parse)
        .and_raise(KeeperSecretsManager::NotationError, 'Invalid notation')

      result = sm.try_get_notation('keeper://invalid/notation')

      expect(result).to eq([])
    end

    it 'returns empty array when record not found' do
      sm = KeeperSecretsManager.new(config: storage)

      # Mock the parser to raise RecordNotFoundError
      allow_any_instance_of(KeeperSecretsManager::Notation::Parser).to receive(:parse)
        .and_raise(KeeperSecretsManager::RecordNotFoundError, 'Record not found')

      result = sm.try_get_notation('keeper://nonexistent-uid/field/password')

      expect(result).to eq([])
    end

    it 'returns empty array for any standard error' do
      sm = KeeperSecretsManager.new(config: storage)

      # Mock the parser to raise StandardError
      allow_any_instance_of(KeeperSecretsManager::Notation::Parser).to receive(:parse)
        .and_raise(StandardError, 'Unexpected error')

      result = sm.try_get_notation('keeper://test/field/value')

      expect(result).to eq([])
    end

    it 'does not raise exceptions' do
      sm = KeeperSecretsManager.new(config: storage)

      # Mock various errors
      allow_any_instance_of(KeeperSecretsManager::Notation::Parser).to receive(:parse)
        .and_raise(KeeperSecretsManager::NotationError, 'Parse error')

      expect {
        sm.try_get_notation('keeper://bad/notation')
      }.not_to raise_error
    end

    it 'logs debug message when notation fails' do
      logger = instance_double(Logger)
      allow(logger).to receive(:debug)
      allow(logger).to receive(:level=)
      allow(Logger).to receive(:new).and_return(logger)

      sm = KeeperSecretsManager.new(config: storage, logger: logger, log_level: Logger::DEBUG)

      allow_any_instance_of(KeeperSecretsManager::Notation::Parser).to receive(:parse)
        .and_raise(KeeperSecretsManager::NotationError, 'Invalid notation')

      expect(logger).to receive(:debug).with(/try_get_notation failed/)

      sm.try_get_notation('keeper://test/bad')
    end
  end
end
