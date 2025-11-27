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

    it 'has thumbnail_url attribute' do
      file = described_class.new

      expect(file).to respond_to(:thumbnail_url)
      expect(file).to respond_to(:thumbnail_url=)
    end

    it 'parses thumbnailUrl from attributes' do
      file = described_class.new(
        'fileUid' => 'file-123',
        'name' => 'image.jpg',
        'url' => 'https://example.com/file',
        'thumbnailUrl' => 'https://example.com/thumb'
      )

      expect(file.thumbnail_url).to eq('https://example.com/thumb')
    end

    it 'supports snake_case thumbnail_url parameter' do
      file = described_class.new(
        'uid' => 'file-123',
        'name' => 'image.jpg',
        'thumbnail_url' => 'https://example.com/thumb'
      )

      expect(file.thumbnail_url).to eq('https://example.com/thumb')
    end

    it 'has last_modified attribute' do
      file = described_class.new

      expect(file).to respond_to(:last_modified)
      expect(file).to respond_to(:last_modified=)
    end

    it 'parses lastModified from attributes' do
      file = described_class.new(
        'fileUid' => 'file-123',
        'name' => 'document.pdf',
        'lastModified' => 1699564800
      )

      expect(file.last_modified).to eq(1699564800)
    end

    it 'supports snake_case last_modified parameter' do
      file = described_class.new(
        'uid' => 'file-123',
        'name' => 'document.pdf',
        'last_modified' => 1699564800
      )

      expect(file.last_modified).to eq(1699564800)
    end
  end

  describe KeeperSecretsManager::Dto::QueryOptions do
    it 'creates options with default values' do
      options = described_class.new

      expect(options.records_filter).to be_nil
      expect(options.folders_filter).to be_nil
      expect(options.request_links).to be_nil
    end

    it 'creates options with records filter' do
      options = described_class.new(records: ['uid-1', 'uid-2'])

      expect(options.records_filter).to eq(['uid-1', 'uid-2'])
    end

    it 'creates options with request_links' do
      options = described_class.new(request_links: true)

      expect(options.request_links).to be true
    end

    it 'creates options with all parameters' do
      options = described_class.new(
        records: ['uid-1'],
        folders: ['folder-1'],
        request_links: true
      )

      expect(options.records_filter).to eq(['uid-1'])
      expect(options.folders_filter).to eq(['folder-1'])
      expect(options.request_links).to be true
    end
  end

  describe KeeperSecretsManager::Dto::CreateOptions do
    it 'creates options with folder_uid only' do
      options = described_class.new(folder_uid: 'folder-123')

      expect(options.folder_uid).to eq('folder-123')
      expect(options.subfolder_uid).to be_nil
    end

    it 'creates options with both folder_uid and subfolder_uid' do
      options = described_class.new(
        folder_uid: 'folder-123',
        subfolder_uid: 'subfolder-456'
      )

      expect(options.folder_uid).to eq('folder-123')
      expect(options.subfolder_uid).to eq('subfolder-456')
    end

    it 'allows setting subfolder_uid after creation' do
      options = described_class.new(folder_uid: 'folder-123')
      options.subfolder_uid = 'subfolder-456'

      expect(options.subfolder_uid).to eq('subfolder-456')
    end
  end

  describe KeeperSecretsManager::Dto::CreatePayload do
    it 'has sub_folder_uid attribute' do
      payload = described_class.new

      expect(payload).to respond_to(:sub_folder_uid)
      expect(payload).to respond_to(:sub_folder_uid=)
    end

    it 'allows setting sub_folder_uid' do
      payload = described_class.new
      payload.sub_folder_uid = 'subfolder-789'

      expect(payload.sub_folder_uid).to eq('subfolder-789')
    end

    it 'converts sub_folder_uid to subFolderUid in JSON' do
      payload = described_class.new
      payload.sub_folder_uid = 'test-subfolder-uid'

      hash = payload.to_h
      expect(hash).to have_key('subFolderUid')
      expect(hash['subFolderUid']).to eq('test-subfolder-uid')
    end
  end

  describe KeeperSecretsManager::Dto::KeeperRecord do
    it 'has inner_folder_uid attribute' do
      record = described_class.new

      expect(record).to respond_to(:inner_folder_uid)
      expect(record).to respond_to(:inner_folder_uid=)
    end

    it 'parses innerFolderUid from API response' do
      record = described_class.new(
        'recordUid' => 'test-uid',
        'folderUid' => 'parent-folder-uid',
        'innerFolderUid' => 'subfolder-uid',
        'data' => { 'title' => 'Test', 'type' => 'login', 'fields' => [] }
      )

      expect(record.folder_uid).to eq('parent-folder-uid')
      expect(record.inner_folder_uid).to eq('subfolder-uid')
    end

    it 'supports snake_case inner_folder_uid parameter' do
      record = described_class.new(
        'uid' => 'test-uid',
        'folder_uid' => 'parent-folder-uid',
        'inner_folder_uid' => 'subfolder-uid',
        'title' => 'Test',
        'type' => 'login',
        'fields' => []
      )

      expect(record.folder_uid).to eq('parent-folder-uid')
      expect(record.inner_folder_uid).to eq('subfolder-uid')
    end

    it 'has links attribute' do
      record = described_class.new

      expect(record).to respond_to(:links)
      expect(record).to respond_to(:links=)
    end

    it 'initializes with empty links array by default' do
      record = described_class.new(
        'uid' => 'test-uid',
        'title' => 'Test',
        'type' => 'login',
        'fields' => []
      )

      expect(record.links).to eq([])
    end

    it 'parses links from API response' do
      record = described_class.new(
        'recordUid' => 'test-uid',
        'data' => { 'title' => 'Test', 'type' => 'login', 'fields' => [] },
        'links' => [
          { 'recordUid' => 'linked-record-1' },
          { 'recordUid' => 'linked-record-2', 'data' => 'encrypted-data', 'path' => '/some/path' }
        ]
      )

      expect(record.links).to be_an(Array)
      expect(record.links.length).to eq(2)
      expect(record.links[0]).to be_a(Hash)
      expect(record.links[0]['recordUid']).to eq('linked-record-1')
      expect(record.links[1]['recordUid']).to eq('linked-record-2')
      expect(record.links[1]['data']).to eq('encrypted-data')
      expect(record.links[1]['path']).to eq('/some/path')
    end

    it 'has is_editable attribute' do
      record = described_class.new

      expect(record).to respond_to(:is_editable)
      expect(record).to respond_to(:is_editable=)
    end

    it 'defaults is_editable to true' do
      record = described_class.new(
        'uid' => 'test-uid',
        'title' => 'Test',
        'type' => 'login',
        'fields' => []
      )

      expect(record.is_editable).to be true
    end

    it 'parses isEditable from API response' do
      record = described_class.new(
        'recordUid' => 'test-uid',
        'data' => { 'title' => 'Test', 'type' => 'login', 'fields' => [] },
        'isEditable' => false
      )

      expect(record.is_editable).to be false
    end

    it 'supports snake_case is_editable parameter' do
      record = described_class.new(
        'uid' => 'test-uid',
        'title' => 'Test',
        'type' => 'login',
        'fields' => [],
        'is_editable' => false
      )

      expect(record.is_editable).to be false
    end
  end

  describe KeeperSecretsManager::Dto::UpdateOptions do
    it 'creates options with default transaction_type' do
      options = described_class.new

      expect(options.transaction_type).to eq('general')
      expect(options.links_to_remove).to eq([])
    end

    it 'creates options with custom transaction_type' do
      options = described_class.new(transaction_type: 'rotation')

      expect(options.transaction_type).to eq('rotation')
    end

    it 'creates options with links_to_remove' do
      options = described_class.new(links_to_remove: ['link-uid-1', 'link-uid-2'])

      expect(options.links_to_remove).to eq(['link-uid-1', 'link-uid-2'])
    end

    it 'creates options with both parameters' do
      options = described_class.new(
        transaction_type: 'rotation',
        links_to_remove: ['link-uid-1']
      )

      expect(options.transaction_type).to eq('rotation')
      expect(options.links_to_remove).to eq(['link-uid-1'])
    end

    it 'allows setting links_to_remove after creation' do
      options = described_class.new
      options.links_to_remove = ['link-uid-1']

      expect(options.links_to_remove).to eq(['link-uid-1'])
    end
  end

  describe KeeperSecretsManager::Dto::UpdatePayload do
    it 'has links2_remove attribute' do
      payload = described_class.new

      expect(payload).to respond_to(:links2_remove)
      expect(payload).to respond_to(:links2_remove=)
    end

    it 'allows setting links2_remove' do
      payload = described_class.new
      payload.links2_remove = ['link-1', 'link-2']

      expect(payload.links2_remove).to eq(['link-1', 'link-2'])
    end

    it 'converts links2_remove to links2Remove in JSON' do
      payload = described_class.new
      payload.links2_remove = ['test-link-uid']

      hash = payload.to_h
      expect(hash).to have_key('links2Remove')
      expect(hash['links2Remove']).to eq(['test-link-uid'])
    end
  end

  describe KeeperSecretsManager::Dto::SecretsManagerResponse do
    it 'has expires_on attribute' do
      response = described_class.new

      expect(response).to respond_to(:expires_on)
      expect(response).to respond_to(:expires_on=)
    end

    it 'initializes with nil expires_on by default' do
      response = described_class.new(records: [], folders: [])

      expect(response.expires_on).to be_nil
    end

    it 'accepts expires_on in initialization' do
      response = described_class.new(
        records: [],
        folders: [],
        expires_on: 1699564800
      )

      expect(response.expires_on).to eq(1699564800)
    end
  end

  describe KeeperSecretsManager::Dto::GetPayload do
    it 'has request_links attribute' do
      payload = described_class.new

      expect(payload).to respond_to(:request_links)
      expect(payload).to respond_to(:request_links=)
    end

    it 'allows setting request_links' do
      payload = described_class.new
      payload.request_links = true

      expect(payload.request_links).to be true
    end

    it 'converts request_links to requestLinks in JSON' do
      payload = described_class.new
      payload.request_links = true

      hash = payload.to_h
      expect(hash).to have_key('requestLinks')
      expect(hash['requestLinks']).to be true
    end
  end

  describe KeeperSecretsManager::Dto::CompleteTransactionPayload do
    it 'creates payload with record_uid' do
      payload = described_class.new
      payload.record_uid = 'test-record-uid'

      expect(payload.record_uid).to eq('test-record-uid')
    end

    it 'includes record_uid in JSON output' do
      payload = described_class.new
      payload.client_version = 'ruby17.2.0'
      payload.client_id = 'test-client-id'
      payload.record_uid = 'test-record-uid'

      hash = payload.to_h
      expect(hash).to have_key('recordUid')
      expect(hash['recordUid']).to eq('test-record-uid')
      expect(hash['clientVersion']).to eq('ruby17.2.0')
      expect(hash['clientId']).to eq('test-client-id')
    end

    it 'converts to proper JSON format' do
      payload = described_class.new
      payload.client_version = 'ruby17.2.0'
      payload.client_id = 'test-client'
      payload.record_uid = 'uid-123'

      json = payload.to_json
      parsed = JSON.parse(json)

      expect(parsed['recordUid']).to eq('uid-123')
      expect(parsed['clientVersion']).to eq('ruby17.2.0')
      expect(parsed['clientId']).to eq('test-client')
    end
  end

  describe KeeperSecretsManager::Dto::QueryOptions do
    it 'creates with default values' do
      options = described_class.new

      expect(options.records_filter).to be_nil
      expect(options.folders_filter).to be_nil
      expect(options.request_links).to be_nil
    end

    it 'accepts records filter' do
      options = described_class.new(records: ['uid1', 'uid2', 'uid3'])

      expect(options.records_filter).to eq(['uid1', 'uid2', 'uid3'])
      expect(options.folders_filter).to be_nil
      expect(options.request_links).to be_nil
    end

    it 'accepts folders filter' do
      options = described_class.new(folders: ['folder1', 'folder2'])

      expect(options.records_filter).to be_nil
      expect(options.folders_filter).to eq(['folder1', 'folder2'])
      expect(options.request_links).to be_nil
    end

    it 'accepts request_links parameter' do
      options = described_class.new(request_links: true)

      expect(options.records_filter).to be_nil
      expect(options.folders_filter).to be_nil
      expect(options.request_links).to be true
    end

    it 'accepts all parameters together' do
      options = described_class.new(
        records: ['uid1', 'uid2'],
        folders: ['folder1'],
        request_links: true
      )

      expect(options.records_filter).to eq(['uid1', 'uid2'])
      expect(options.folders_filter).to eq(['folder1'])
      expect(options.request_links).to be true
    end

    it 'allows modifying filters after creation' do
      options = described_class.new

      options.records_filter = ['new_uid']
      options.folders_filter = ['new_folder']
      options.request_links = true

      expect(options.records_filter).to eq(['new_uid'])
      expect(options.folders_filter).to eq(['new_folder'])
      expect(options.request_links).to be true
    end

    it 'handles nil filters' do
      options = described_class.new(records: nil, folders: nil, request_links: nil)

      expect(options.records_filter).to be_nil
      expect(options.folders_filter).to be_nil
      expect(options.request_links).to be_nil
    end

    it 'handles empty array filters' do
      options = described_class.new(records: [], folders: [])

      expect(options.records_filter).to eq([])
      expect(options.folders_filter).to eq([])
    end

    it 'accepts false for request_links' do
      options = described_class.new(request_links: false)

      expect(options.request_links).to be false
    end
  end
end
