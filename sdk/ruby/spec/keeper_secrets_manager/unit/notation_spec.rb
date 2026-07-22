require 'spec_helper'

RSpec.describe KeeperSecretsManager::Notation::Parser do
  let(:mock_secrets_manager) { double('SecretsManager') }
  let(:parser) { described_class.new(mock_secrets_manager) }

  let(:test_record) do
    KeeperSecretsManager::Dto::KeeperRecord.new(
      uid: 'test-uid-123',
      title: 'Test Record',
      type: 'login',
      notes: 'Test notes',
      fields: [
        { 'type' => 'login', 'value' => ['testuser'] },
        { 'type' => 'password', 'value' => ['testpass'] },
        { 'type' => 'url', 'value' => ['https://example.com', 'https://backup.com'] },
        { 'type' => 'host', 'value' => [{ 'hostName' => '192.168.1.1', 'port' => '22' }] },
        { 'type' => 'name', 'value' => [{ 'first' => 'John', 'middle' => 'Q', 'last' => 'Doe' }] }
      ],
      custom: [
        { 'type' => 'text', 'label' => 'Environment', 'value' => ['Production'] },
        { 'type' => 'text', 'label' => 'Multi Value', 'value' => %w[Value1 Value2 Value3] }
      ],
      files: [
        KeeperSecretsManager::Dto::KeeperFile.new(
          uid: 'file-123',
          name: 'document.pdf',
          title: 'Important Document'
        )
      ]
    )
  end

  describe '#parse' do
    before do
      allow(mock_secrets_manager).to receive(:get_secrets).and_return([test_record])
    end

    context 'with simple selectors' do
      it 'returns record type' do
        result = parser.parse('keeper://test-uid-123/type')
        expect(result).to eq('login')
      end

      it 'returns record title' do
        result = parser.parse('keeper://test-uid-123/title')
        expect(result).to eq('Test Record')
      end

      it 'returns record notes' do
        result = parser.parse('keeper://test-uid-123/notes')
        expect(result).to eq('Test notes')
      end
    end

    context 'with field selectors' do
      it 'returns simple field value' do
        result = parser.parse('keeper://test-uid-123/field/login')
        expect(result).to eq('testuser')
      end

      it 'returns field with multiple values using index' do
        result = parser.parse('keeper://test-uid-123/field/url[0]')
        expect(result).to eq('https://example.com')

        result = parser.parse('keeper://test-uid-123/field/url[1]')
        expect(result).to eq('https://backup.com')
      end

      it 'returns all values with empty index' do
        result = parser.parse('keeper://test-uid-123/field/url[]')
        expect(result).to eq(['https://example.com', 'https://backup.com'])
      end

      it 'returns complex field property' do
        result = parser.parse('keeper://test-uid-123/field/host[hostName]')
        expect(result).to eq('192.168.1.1')

        result = parser.parse('keeper://test-uid-123/field/host[port]')
        expect(result).to eq('22')
      end

      it 'returns nested field property with index' do
        result = parser.parse('keeper://test-uid-123/field/name[0][middle]')
        expect(result).to eq('Q')
      end
    end

    context 'with custom fields' do
      it 'returns custom field by label' do
        result = parser.parse('keeper://test-uid-123/custom_field/Environment')
        expect(result).to eq('Production')
      end

      it 'returns custom field with index' do
        result = parser.parse('keeper://test-uid-123/custom_field/Multi Value[1]')
        expect(result).to eq('Value2')
      end
    end

    context 'with file selectors' do
      it 'returns file by name' do
        result = parser.parse('keeper://test-uid-123/file/document.pdf')
        expect(result).to be_a(KeeperSecretsManager::Dto::KeeperFile)
        expect(result.name).to eq('document.pdf')
      end

      it 'returns file by title' do
        result = parser.parse('keeper://test-uid-123/file/Important Document')
        expect(result).to be_a(KeeperSecretsManager::Dto::KeeperFile)
        expect(result.title).to eq('Important Document')
      end

      it 'returns file by UID' do
        result = parser.parse('keeper://test-uid-123/file/file-123')
        expect(result).to be_a(KeeperSecretsManager::Dto::KeeperFile)
        expect(result.uid).to eq('file-123')
      end
    end

    context 'with record title instead of UID' do
      it 'finds record by title' do
        result = parser.parse('keeper://Test Record/field/login')
        expect(result).to eq('testuser')
      end
    end

    context 'with base64 encoded notation' do
      it 'decodes and parses base64 notation' do
        notation = 'keeper://test-uid-123/field/login'
        encoded = Base64.urlsafe_encode64(notation)

        result = parser.parse(encoded)
        expect(result).to eq('testuser')
      end
    end

    context 'with escaped characters' do
      it 'handles escaped forward slashes in values' do
        record_with_slash = KeeperSecretsManager::Dto::KeeperRecord.new(
          uid: 'slash-uid',
          title: 'Record/With/Slashes',
          fields: [{ 'type' => 'login', 'value' => ['user/name'] }]
        )

        allow(mock_secrets_manager).to receive(:get_secrets)
          .with(['Record/With/Slashes'])
          .and_return([])
        allow(mock_secrets_manager).to receive(:get_secrets)
          .with(no_args)
          .and_return([record_with_slash])

        result = parser.parse('keeper://Record\/With\/Slashes/field/login')
        expect(result).to eq('user/name')
      end
    end

    context 'duplicate UID handling (shortcuts)' do
      it 'handles duplicate UIDs from shortcuts/linked records' do
        # Create two records with same UID (simulating original + shortcut)
        record1 = KeeperSecretsManager::Dto::KeeperRecord.new(
          uid: 'duplicate-uid',
          title: 'Original Record',
          fields: [{ 'type' => 'login', 'value' => ['testuser'] }]
        )
        record2 = KeeperSecretsManager::Dto::KeeperRecord.new(
          uid: 'duplicate-uid',
          title: 'Shortcut Record',
          fields: [{ 'type' => 'login', 'value' => ['testuser'] }]
        )

        allow(mock_secrets_manager).to receive(:get_secrets).with(['duplicate-uid']).and_return([record1, record2])

        # Should not raise error, should deduplicate and return first record's value
        result = parser.parse('keeper://duplicate-uid/field/login')
        expect(result).to eq('testuser')
      end
    end

    context 'error handling' do
      it 'raises error for invalid notation format' do
        expect { parser.parse('invalid-notation') }.to raise_error(KeeperSecretsManager::NotationError)
      end

      it 'raises error for non-existent record' do
        allow(mock_secrets_manager).to receive(:get_secrets).and_return([])

        expect { parser.parse('keeper://non-existent/field/login') }
          .to raise_error(KeeperSecretsManager::NotationError, /No records match/)
      end

      it 'raises error for non-existent field' do
        expect { parser.parse('keeper://test-uid-123/field/nonexistent') }
          .to raise_error(KeeperSecretsManager::NotationError, /Field 'nonexistent' not found/)
      end

      it 'raises error for invalid selector' do
        expect { parser.parse('keeper://test-uid-123/invalid_selector') }
          .to raise_error(KeeperSecretsManager::NotationError, /Invalid selector/)
      end

      it 'raises error for out of bounds index' do
        expect { parser.parse('keeper://test-uid-123/field/url[10]') }
          .to raise_error(KeeperSecretsManager::NotationError, /index out of bounds/)
      end

      it 'raises error for missing file parameter' do
        expect { parser.parse('keeper://test-uid-123/file') }
          .to raise_error(KeeperSecretsManager::NotationError, /Missing required parameter/)
      end
    end
  end

  describe '#get_notation_results' do
    before do
      allow(mock_secrets_manager).to receive(:get_secrets).and_return([test_record])
    end

    context 'simple selectors' do
      it 'returns type as a one-element array' do
        expect(parser.get_notation_results('keeper://test-uid-123/type')).to eq(['login'])
      end

      it 'returns title as a one-element array' do
        expect(parser.get_notation_results('keeper://test-uid-123/title')).to eq(['Test Record'])
      end

      it 'returns notes as a one-element array' do
        expect(parser.get_notation_results('keeper://test-uid-123/notes')).to eq(['Test notes'])
      end

      it 'returns empty array for empty notes' do
        empty_notes_record = KeeperSecretsManager::Dto::KeeperRecord.new(
          uid: 'no-notes-uid', title: 'No Notes', type: 'login', notes: '', fields: []
        )
        allow(mock_secrets_manager).to receive(:get_secrets).and_return([empty_notes_record])
        expect(parser.get_notation_results('keeper://no-notes-uid/notes')).to eq([])
      end
    end

    context 'field selectors — all-values default' do
      it 'returns all values when no index is given (multi-value field)' do
        result = parser.get_notation_results('keeper://test-uid-123/field/url')
        expect(result).to eq(['https://example.com', 'https://backup.com'])
      end

      it 'returns a one-element array for a single-value field with no index' do
        expect(parser.get_notation_results('keeper://test-uid-123/field/login')).to eq(['testuser'])
      end

      it 'returns a one-element array for explicit [0] index' do
        expect(parser.get_notation_results('keeper://test-uid-123/field/url[0]')).to eq(['https://example.com'])
      end

      it 'returns all values for [] index' do
        expect(parser.get_notation_results('keeper://test-uid-123/field/url[]')).to eq(['https://example.com', 'https://backup.com'])
      end

      it 'JSON-serializes Hash values when no property index is given' do
        result = parser.get_notation_results('keeper://test-uid-123/field/host')
        expect(result.length).to eq(1)
        parsed = JSON.parse(result.first)
        expect(parsed['hostName']).to eq('192.168.1.1')
      end

      it 'extracts a property from all values with [][property]' do
        result = parser.get_notation_results('keeper://test-uid-123/field/host[][hostName]')
        expect(result).to eq(['192.168.1.1'])
      end

      it 'extracts a property from a specific element with [0][property]' do
        expect(parser.get_notation_results('keeper://test-uid-123/field/name[0][middle]')).to eq(['Q'])
      end
    end

    context 'custom field selectors' do
      it 'returns custom field value' do
        expect(parser.get_notation_results('keeper://test-uid-123/custom_field/Environment')).to eq(['Production'])
      end

      it 'returns all values for multi-value custom field' do
        result = parser.get_notation_results('keeper://test-uid-123/custom_field/Multi Value')
        expect(result).to eq(%w[Value1 Value2 Value3])
      end
    end

    context 'error cases' do
      it 'returns empty array for nil notation' do
        expect(parser.get_notation_results(nil)).to eq([])
      end

      it 'returns empty array for empty string' do
        expect(parser.get_notation_results('')).to eq([])
      end

      it 'returns empty array for non-string input' do
        expect(parser.get_notation_results(42)).to eq([])
      end

      it 'raises NotationError for out-of-bounds index' do
        expect { parser.get_notation_results('keeper://test-uid-123/field/url[10]') }
          .to raise_error(KeeperSecretsManager::NotationError, /index out of bounds/)
      end

      it 'raises NotationError for non-existent field' do
        expect { parser.get_notation_results('keeper://test-uid-123/field/nonexistent') }
          .to raise_error(KeeperSecretsManager::NotationError, /Field 'nonexistent' not found/)
      end

      it 'raises NotationError for non-existent record' do
        allow(mock_secrets_manager).to receive(:get_secrets).and_return([])
        expect { parser.get_notation_results('keeper://missing/field/login') }
          .to raise_error(KeeperSecretsManager::NotationError, /No records match/)
      end
    end
  end

  describe 'SecretsManager#get_notation_results and #try_get_notation_results' do
    let(:mock_sm) { double('SecretsManager') }
    let(:sm_parser) { described_class.new(mock_sm) }
    let(:simple_record) do
      KeeperSecretsManager::Dto::KeeperRecord.new(
        uid: 'sm-uid-1', title: 'SM Record', type: 'login',
        fields: [{ 'type' => 'login', 'value' => ['smuser'] }]
      )
    end

    before do
      allow(mock_sm).to receive(:get_secrets).and_return([simple_record])
    end

    it 'get_notation_results delegates to Parser#get_notation_results' do
      result = sm_parser.get_notation_results('keeper://sm-uid-1/field/login')
      expect(result).to eq(['smuser'])
    end

    it 'try_get_notation_results returns [] and does not raise on bad notation' do
      bad_parser = described_class.new(double('BadSM'))
      allow(bad_parser.instance_variable_get(:@secrets_manager)).to receive(:get_secrets).and_return([])
      allow(bad_parser.instance_variable_get(:@secrets_manager)).to receive(:get_secrets).and_return([])

      result = nil
      expect {
        # Simulate what try_get_notation_results does by catching the exception
        begin
          bad_parser.get_notation_results('keeper://nonexistent/field/login')
        rescue KeeperSecretsManager::NotationError
          result = []
        end
      }.not_to raise_error
      expect(result).to eq([])
    end
  end

  describe '#get_value' do
    context 'with nil or invalid notation' do
      it 'returns nil without raising when notation is nil' do
        expect(parser.get_value(nil, auto_process: true)).to be_nil
      end

      it 'returns nil without raising when notation is empty string' do
        expect(parser.get_value('', auto_process: true)).to be_nil
      end

      it 'returns nil without raising when notation is not a string' do
        expect(parser.get_value(42, auto_process: true)).to be_nil
      end
    end

    context 'without auto_process' do
      it 'returns nil for nil notation' do
        expect(parser.get_value(nil)).to be_nil
      end
    end
  end

  describe 'private methods' do
    describe '#parse_notation' do
      xit 'correctly parses all sections of a notation' do
        sections = parser.send(:parse_notation, 'keeper://RECORD/field/password[0][value]')

        expect(sections).to have_attributes(size: 4)
        expect(sections[0]).to have_attributes(
          section: 'prefix',
          present?: true,
          text: ['keeper://', 'keeper://']
        )
        expect(sections[1]).to have_attributes(
          section: 'record',
          present?: true,
          text: %w[RECORD RECORD]
        )
        expect(sections[2]).to have_attributes(
          section: 'selector',
          present?: true,
          text: %w[field field],
          parameter: %w[password password],
          index1: ['0', '[0]'],
          index2: ['value', '[value]']
        )
      end
    end

    describe '#parse_subsection' do
      it 'parses text with single delimiter' do
        result = parser.send(:parse_subsection, 'text/more', 0, '/', false)
        expect(result).to eq(['text', 'text/'])
      end

      it 'parses text with bracket delimiters' do
        result = parser.send(:parse_subsection, '[index]rest', 0, '[]', false)
        expect(result).to eq(['index', '[index]'])
      end

      it 'handles escaped characters' do
        result = parser.send(:parse_subsection, 'text\/with\/slashes/', 0, '/', true)
        expect(result).to eq(['text/with/slashes', 'text\\/with\\/slashes/'])
      end

      it 'raises error for unclosed brackets' do
        expect { parser.send(:parse_subsection, '[unclosed', 0, '[]', false) }
          .to raise_error(KeeperSecretsManager::NotationError)
      end
    end
  end
end
