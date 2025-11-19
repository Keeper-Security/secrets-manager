require 'spec_helper'

RSpec.describe KeeperSecretsManager::Dto do
  describe KeeperSecretsManager::Dto::KeeperRecord do
    describe 'flexible record creation' do
      it 'creates record from hash with string keys' do
        record = described_class.new(
          'title' => 'Test Record',
          'type' => 'login',
          'fields' => [
            { 'type' => 'login', 'value' => ['username'] }
          ]
        )

        expect(record.title).to eq('Test Record')
        expect(record.type).to eq('login')
        expect(record.fields.size).to eq(1)
      end

      it 'creates record from hash with symbol keys' do
        record = described_class.new(
          title: 'Test Record',
          type: 'login',
          fields: [
            { 'type' => 'password', 'value' => ['secret'] }
          ]
        )

        expect(record.title).to eq('Test Record')
        expect(record.fields.first['type']).to eq('password')
      end

      it 'handles API response format' do
        api_data = {
          'recordUid' => 'uid-123',
          'revision' => 5,
          'data' => {
            'title' => 'API Record',
            'type' => 'login',
            'fields' => [],
            'custom' => []
          }
        }

        record = described_class.new(api_data)
        expect(record.uid).to eq('uid-123')
        expect(record.revision).to eq(5)
        expect(record.title).to eq('API Record')
      end
    end

    describe 'field operations' do
      let(:record) do
        described_class.new(
          title: 'Test',
          fields: [
            { 'type' => 'login', 'value' => ['user1'] },
            { 'type' => 'password', 'value' => ['pass1'] },
            { 'type' => 'host', 'label' => 'Server', 'value' => [{ 'hostName' => '192.168.1.1' }] }
          ],
          custom: [
            { 'type' => 'text', 'label' => 'Notes', 'value' => ['Important info'] }
          ]
        )
      end

      it 'finds field by type' do
        field = record.get_field('login')
        expect(field).not_to be_nil
        expect(field['value']).to eq(['user1'])
      end

      it 'finds field by label' do
        field = record.get_field('Server')
        expect(field).not_to be_nil
        expect(field['type']).to eq('host')
      end

      it 'finds custom field' do
        field = record.get_field('Notes')
        expect(field).not_to be_nil
        expect(field['value']).to eq(['Important info'])
      end

      it 'returns nil for non-existent field' do
        field = record.get_field('nonexistent')
        expect(field).to be_nil
      end

      it 'gets field value as array' do
        value = record.get_field_value('login')
        expect(value).to eq(['user1'])
      end

      it 'gets single field value' do
        value = record.get_field_value_single('login')
        expect(value).to eq('user1')
      end

      it 'sets new field' do
        record.set_field('url', 'https://example.com')
        field = record.get_field('url')
        expect(field['value']).to eq(['https://example.com'])
      end

      it 'updates existing field' do
        record.set_field('login', 'user2')
        value = record.get_field_value_single('login')
        expect(value).to eq('user2')
      end

      it 'ensures field values are arrays' do
        record.set_field('new_field', 'single_value')
        field = record.get_field('new_field')
        expect(field['value']).to be_an(Array)
        expect(field['value']).to eq(['single_value'])
      end
    end

    describe 'dynamic field access' do
      let(:record) do
        described_class.new(
          fields: [
            { 'type' => 'login', 'value' => ['testuser'] },
            { 'type' => 'password', 'value' => ['testpass'] }
          ]
        )
      end

      it 'supports dynamic getter methods' do
        expect(record.login).to eq('testuser')
        expect(record.password).to eq('testpass')
      end

      it 'supports dynamic setter methods' do
        record.login = 'newuser'
        expect(record.get_field_value_single('login')).to eq('newuser')
      end

      it 'responds to common field types' do
        expect(record).to respond_to(:login)
        expect(record).to respond_to(:password)
        expect(record).to respond_to(:url)
      end

      it 'raises NoMethodError for unknown methods' do
        expect { record.unknown_method }.to raise_error(NoMethodError)
      end
    end

    describe '#to_h' do
      it 'converts record to hash for API' do
        record = described_class.new(
          uid: 'test-uid',
          title: 'Test',
          type: 'login',
          fields: [{ 'type' => 'login', 'value' => ['user'] }],
          notes: 'Test notes'
        )

        hash = record.to_h
        # to_h returns data structure for encryption (no uid/folder_uid/revision)
        # Those fields are in the outer payload, not in the encrypted data
        expect(hash).to include(
          'title' => 'Test',
          'type' => 'login',
          'notes' => 'Test notes'
        )
        expect(hash['fields']).to be_an(Array)
        expect(hash).not_to have_key('uid')
        expect(hash).not_to have_key('folder_uid')
      end

      it 'excludes nil values' do
        record = described_class.new(title: 'Test')
        hash = record.to_h

        expect(hash).to have_key('title')
        expect(hash).not_to have_key('folder_uid')
      end
    end
  end

  describe KeeperSecretsManager::Dto::KeeperFolder do
    it 'creates folder from attributes' do
      folder = described_class.new(
        'folderUid' => 'folder-123',
        'name' => 'My Folder',
        'parentUid' => 'parent-123'
      )

      expect(folder.uid).to eq('folder-123')
      expect(folder.name).to eq('My Folder')
      expect(folder.parent_uid).to eq('parent-123')
    end

    it 'defaults to user_folder type' do
      folder = described_class.new(name: 'Test')
      expect(folder.folder_type).to eq('user_folder')
    end
  end

  describe KeeperSecretsManager::Dto::KeeperFile do
    it 'creates file from attributes' do
      file = described_class.new(
        'fileUid' => 'file-123',
        'name' => 'document.pdf',
        'size' => 1024,
        'mimeType' => 'application/pdf'
      )

      expect(file.uid).to eq('file-123')
      expect(file.name).to eq('document.pdf')
      expect(file.size).to eq(1024)
      expect(file.mime_type).to eq('application/pdf')
    end

    it 'uses name as title if title not provided' do
      file = described_class.new(name: 'test.txt')
      expect(file.title).to eq('test.txt')
    end
  end
end
