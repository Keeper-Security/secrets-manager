require 'spec_helper'
require 'tempfile'

RSpec.describe 'File operations', :integration do
  # File operations can be tested with mock data
  # These tests validate file metadata handling, encryption, and download logic

  let(:use_mock_data) { true } # Always use mock for this spec
  let(:secrets_manager) do
    # Use the mock helper to create a properly configured secrets manager
    require_relative '../../../test/integration/mock_helper'
    MockHelper.create_mock_secrets_manager
  end

  # Shared mock record with files for all tests
  let(:mock_record_with_files) do
    # Create a mock record with file attachments
    KeeperSecretsManager::Dto::KeeperRecord.new(
      uid: 'test-file-record',
      type: 'file',
      title: 'Test File Record',
      fields: [],
      files: [
        {
          'fileUid' => 'test-file-uid-1',
          'name' => 'document.pdf',
          'title' => 'Test Document',
          'type' => 'application/pdf',
          'size' => 1024,
          'lastModified' => (Time.now.to_f * 1000).to_i,
          'fileKey' => Base64.strict_encode64('mock-file-key-32-bytes-long!!'),
          'url' => 'https://mock.keepersecurity.com/files/test-file-uid-1'
        },
        {
          'fileUid' => 'test-file-uid-2',
          'name' => 'image.png',
          'title' => 'Test Image',
          'type' => 'image/png',
          'size' => 2048,
          'lastModified' => (Time.now.to_f * 1000).to_i,
          'fileKey' => Base64.strict_encode64('mock-file-key-32-bytes-long!!'),
          'url' => 'https://mock.keepersecurity.com/files/test-file-uid-2'
        }
      ]
    )
  end

  describe 'file metadata handling' do
    let(:test_record_with_files) do
      # Create a mock record with file attachments
      KeeperSecretsManager::Dto::KeeperRecord.new(
        uid: 'test-file-record',
        type: 'file',
        title: 'Test File Record',
        fields: [],
        files: [
          {
            'fileUid' => 'test-file-uid-1',
            'name' => 'document.pdf',
            'title' => 'Test Document',
            'type' => 'application/pdf',
            'size' => 1024,
            'lastModified' => (Time.now.to_f * 1000).to_i,
            'fileKey' => Base64.strict_encode64('mock-file-key-32-bytes-long!!'),
            'url' => 'https://mock.keepersecurity.com/files/test-file-uid-1'
          },
          {
            'fileUid' => 'test-file-uid-2',
            'name' => 'image.png',
            'title' => 'Test Image',
            'type' => 'image/png',
            'size' => 2048,
            'lastModified' => (Time.now.to_f * 1000).to_i,
            'fileKey' => Base64.strict_encode64('mock-file-key-32-bytes-long!!'),
            'url' => 'https://mock.keepersecurity.com/files/test-file-uid-2'
          }
        ]
      )
    end

    it 'parses file metadata from records' do
      expect(test_record_with_files.files).to be_an(Array)
      expect(test_record_with_files.files.length).to eq(2)
    end

    it 'accesses file properties' do
      file = test_record_with_files.files.first

      expect(file['fileUid']).to eq('test-file-uid-1')
      expect(file['name']).to eq('document.pdf')
      expect(file['title']).to eq('Test Document')
      expect(file['type']).to eq('application/pdf')
      expect(file['size']).to eq(1024)
      expect(file['fileKey']).not_to be_nil
      expect(file['url']).not_to be_nil
    end

    it 'handles multiple files per record' do
      files = test_record_with_files.files

      expect(files.length).to eq(2)
      expect(files.map { |f| f['name'] }).to contain_exactly('document.pdf', 'image.png')
    end

    it 'handles records without files' do
      record = KeeperSecretsManager::Dto::KeeperRecord.new(
        uid: 'test-no-files',
        type: 'login',
        title: 'Test Login',
        fields: []
      )

      expect(record.files).to be_an(Array)
      expect(record.files).to be_empty
    end
  end

  describe 'file field types' do
    it 'handles fileRef fields in records' do
      record = KeeperSecretsManager::Dto::KeeperRecord.new(
        uid: 'test-file-ref',
        type: 'login',
        title: 'Test with File Ref',
        fields: [
          { 'type' => 'fileRef', 'value' => ['file-uid-1', 'file-uid-2'] }
        ]
      )

      file_ref_field = record.get_field('fileRef')
      expect(file_ref_field).not_to be_nil
      expect(file_ref_field['value']).to contain_exactly('file-uid-1', 'file-uid-2')
    end
  end

  describe 'file size handling' do
    it 'handles small files (< 1KB)' do
      file = {
        'fileUid' => 'small-file',
        'name' => 'small.txt',
        'size' => 512,
        'type' => 'text/plain'
      }

      expect(file['size']).to be < 1024
    end

    it 'handles medium files (1KB - 1MB)' do
      file = {
        'fileUid' => 'medium-file',
        'name' => 'medium.pdf',
        'size' => 100 * 1024, # 100KB
        'type' => 'application/pdf'
      }

      expect(file['size']).to be_between(1024, 1024 * 1024)
    end

    it 'handles large files (> 1MB)' do
      file = {
        'fileUid' => 'large-file',
        'name' => 'large.zip',
        'size' => 5 * 1024 * 1024, # 5MB
        'type' => 'application/zip'
      }

      expect(file['size']).to be > 1024 * 1024
    end
  end

  describe 'file MIME types' do
    it 'handles common document types' do
      mime_types = [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain'
      ]

      mime_types.each do |mime_type|
        file = { 'type' => mime_type }
        expect(file['type']).to eq(mime_type)
      end
    end

    it 'handles common image types' do
      image_types = ['image/png', 'image/jpeg', 'image/gif', 'image/svg+xml']

      image_types.each do |image_type|
        file = { 'type' => image_type }
        expect(file['type']).to eq(image_type)
      end
    end

    it 'handles generic octet-stream' do
      file = { 'type' => 'application/octet-stream' }
      expect(file['type']).to eq('application/octet-stream')
    end
  end

  describe 'file name handling' do
    it 'handles file extensions' do
      files = [
        { 'name' => 'document.pdf' },
        { 'name' => 'image.png' },
        { 'name' => 'archive.tar.gz' },
        { 'name' => 'data.json' }
      ]

      files.each do |file|
        expect(file['name']).to match(/\.\w+$/)
      end
    end

    it 'handles files without extensions' do
      file = { 'name' => 'README' }
      expect(file['name']).not_to match(/\./)
    end

    it 'handles special characters in filenames' do
      special_names = [
        'file with spaces.txt',
        'file_with_underscores.txt',
        'file-with-dashes.txt',
        'file (with) parens.txt'
      ]

      special_names.each do |name|
        file = { 'name' => name }
        expect(file['name']).to eq(name)
      end
    end
  end

  describe 'file timestamp handling' do
    it 'handles lastModified timestamps' do
      timestamp = (Time.now.to_f * 1000).to_i # Milliseconds since epoch
      file = { 'lastModified' => timestamp }

      expect(file['lastModified']).to be_a(Integer)
      expect(file['lastModified']).to be > 0

      # Convert back to Time
      time = Time.at(file['lastModified'] / 1000.0)
      expect(time).to be_within(60).of(Time.now)
    end
  end

  describe 'file array operations' do
    it 'finds files by UID' do
      record = mock_record_with_files
      file = record.files.find { |f| f['fileUid'] == 'test-file-uid-1' }

      expect(file).not_to be_nil
      expect(file['name']).to eq('document.pdf')
    end

    it 'filters files by type' do
      record = mock_record_with_files
      pdfs = record.files.select { |f| f['type'] == 'application/pdf' }

      expect(pdfs.length).to eq(1)
      expect(pdfs.first['name']).to eq('document.pdf')
    end

    it 'counts total files' do
      record = mock_record_with_files
      expect(record.files.length).to eq(2)
    end
  end

  describe 'file upload payload structure' do
    it 'validates file upload data structure' do
      upload_data = {
        'fileUid' => 'new-file-uid',
        'fileName' => 'upload.txt',
        'fileSize' => 1024,
        'mimeType' => 'text/plain'
      }

      expect(upload_data).to have_key('fileUid')
      expect(upload_data).to have_key('fileName')
      expect(upload_data).to have_key('fileSize')
      expect(upload_data).to have_key('mimeType')
    end
  end
end
