require 'spec_helper'

RSpec.describe 'Folder hierarchy operations', :integration do
  # Tests FolderManager functionality with mock folder data
  # These operations work on decrypted folder objects

  let(:secrets_manager) do
    require_relative '../../../test/integration/mock_helper'
    MockHelper.create_mock_secrets_manager
  end

  let(:flat_folders) do
    [
      KeeperSecretsManager::Dto::KeeperFolder.new(
        'folderUid' => 'root-folder-1',
        'name' => 'Root Folder 1',
        'parent' => nil
      ),
      KeeperSecretsManager::Dto::KeeperFolder.new(
        'folderUid' => 'child-folder-1',
        'name' => 'Child Folder 1',
        'parent' => 'root-folder-1'
      ),
      KeeperSecretsManager::Dto::KeeperFolder.new(
        'folderUid' => 'grandchild-folder-1',
        'name' => 'Grandchild Folder 1',
        'parent' => 'child-folder-1'
      ),
      KeeperSecretsManager::Dto::KeeperFolder.new(
        'folderUid' => 'root-folder-2',
        'name' => 'Root Folder 2',
        'parent' => nil
      )
    ]
  end

  describe KeeperSecretsManager::FolderManager do
    describe '#build_folder_tree' do
      let(:folder_manager) { described_class.new(flat_folders) }

      it 'builds tree structure from flat folder list' do
        tree = folder_manager.build_folder_tree

        expect(tree).to be_an(Array)
        expect(tree.length).to eq(2) # Two root folders
      end

      it 'assigns children to parent folders' do
        tree = folder_manager.build_folder_tree

        root1 = tree.find { |node| node[:folder].uid == 'root-folder-1' }
        expect(root1[:children]).to be_an(Array)
        expect(root1[:children].length).to eq(1)
        expect(root1[:children].first[:folder].uid).to eq('child-folder-1')
      end

      it 'builds multi-level hierarchy' do
        tree = folder_manager.build_folder_tree

        root1 = tree.find { |node| node[:folder].uid == 'root-folder-1' }
        child = root1[:children].first
        grandchild = child[:children].first

        expect(grandchild[:folder].uid).to eq('grandchild-folder-1')
        expect(grandchild[:folder].name).to eq('Grandchild Folder 1')
      end

      it 'handles empty folder list' do
        empty_manager = described_class.new([])
        tree = empty_manager.build_folder_tree

        expect(tree).to be_an(Array)
        expect(tree).to be_empty
      end

      it 'handles orphaned folders (parent not found)' do
        orphaned = [
          KeeperSecretsManager::Dto::KeeperFolder.new(
            'folderUid' => 'orphan',
            'name' => 'Orphaned Folder',
            'parent' => 'non-existent-parent'
          )
        ]

        orphan_manager = described_class.new(orphaned)
        tree = orphan_manager.build_folder_tree

        # Orphaned folders should still appear (implementation dependent)
        expect(tree).to be_an(Array)
      end
    end

    describe '#get_folder_path' do
      let(:folder_manager) { described_class.new(flat_folders) }

      it 'returns path for root folder' do
        path = folder_manager.get_folder_path('root-folder-1')

        expect(path).to eq('Root Folder 1')
      end

      it 'returns path for child folder' do
        path = folder_manager.get_folder_path('child-folder-1')

        expect(path).to eq('Root Folder 1/Child Folder 1')
      end

      it 'returns path for deeply nested folder' do
        path = folder_manager.get_folder_path('grandchild-folder-1')

        expect(path).to eq('Root Folder 1/Child Folder 1/Grandchild Folder 1')
      end

      it 'returns nil for non-existent folder' do
        path = folder_manager.get_folder_path('non-existent')

        expect(path).to be_nil
      end
    end

    describe '#get_ancestors' do
      let(:folder_manager) { described_class.new(flat_folders) }

      it 'returns empty array for root folder' do
        ancestors = folder_manager.get_ancestors('root-folder-1')

        expect(ancestors).to be_an(Array)
        expect(ancestors).to be_empty
      end

      it 'returns parent for child folder' do
        ancestors = folder_manager.get_ancestors('child-folder-1')

        expect(ancestors.length).to eq(1)
        expect(ancestors.first.uid).to eq('root-folder-1')
      end

      it 'returns all ancestors for deeply nested folder' do
        ancestors = folder_manager.get_ancestors('grandchild-folder-1')

        expect(ancestors.length).to eq(2)
        expect(ancestors.map(&:uid)).to eq(['child-folder-1', 'root-folder-1'])
      end

      it 'returns empty array for non-existent folder' do
        ancestors = folder_manager.get_ancestors('non-existent')

        expect(ancestors).to be_an(Array)
        expect(ancestors).to be_empty
      end
    end

    describe '#get_descendants' do
      let(:folder_manager) { described_class.new(flat_folders) }

      it 'returns all descendants for root folder' do
        descendants = folder_manager.get_descendants('root-folder-1')

        expect(descendants.length).to eq(2) # Child and grandchild
        expect(descendants.map(&:uid)).to contain_exactly('child-folder-1', 'grandchild-folder-1')
      end

      it 'returns direct and indirect descendants' do
        descendants = folder_manager.get_descendants('root-folder-1')

        # Should include both child and grandchild
        child = descendants.find { |f| f.uid == 'child-folder-1' }
        grandchild = descendants.find { |f| f.uid == 'grandchild-folder-1' }

        expect(child).not_to be_nil
        expect(grandchild).not_to be_nil
      end

      it 'returns empty array for leaf folders' do
        descendants = folder_manager.get_descendants('grandchild-folder-1')

        expect(descendants).to be_an(Array)
        expect(descendants).to be_empty
      end

      it 'returns empty array for non-existent folder' do
        descendants = folder_manager.get_descendants('non-existent')

        expect(descendants).to be_an(Array)
        expect(descendants).to be_empty
      end
    end

    describe '#find_folder_by_name' do
      let(:folder_manager) { described_class.new(flat_folders) }

      it 'finds folder by name' do
        folder = folder_manager.find_folder_by_name('Grandchild Folder 1')

        expect(folder).not_to be_nil
        expect(folder.uid).to eq('grandchild-folder-1')
      end

      it 'finds folder by name within specific parent' do
        folder = folder_manager.find_folder_by_name('Child Folder 1', parent_uid: 'root-folder-1')

        expect(folder).not_to be_nil
        expect(folder.uid).to eq('child-folder-1')
        expect(folder.parent_uid).to eq('root-folder-1')
      end

      it 'returns nil for non-existent name' do
        folder = folder_manager.find_folder_by_name('Non Existent Folder')

        expect(folder).to be_nil
      end
    end

    describe 'folder tree traversal' do
      let(:folder_manager) { described_class.new(flat_folders) }

      it 'allows traversing folder tree structure' do
        tree = folder_manager.build_folder_tree

        # Find root folder node
        root_node = tree.find { |node| node[:folder].uid == 'root-folder-1' }
        expect(root_node[:children].length).to eq(1)

        # Check child node
        child_node = root_node[:children].first
        expect(child_node[:folder].uid).to eq('child-folder-1')
        expect(child_node[:children].length).to eq(1)

        # Check grandchild node
        grandchild_node = child_node[:children].first
        expect(grandchild_node[:folder].uid).to eq('grandchild-folder-1')
        expect(grandchild_node[:children]).to be_empty
      end

      it 'provides parent references in folder objects' do
        child = flat_folders.find { |f| f.uid == 'child-folder-1' }

        expect(child.parent_uid).to eq('root-folder-1')
      end
    end
  end

  describe 'integration with SecretsManager' do
    it 'retrieves folders from mock API' do
      folders = secrets_manager.get_folders

      expect(folders).to be_an(Array)
      expect(folders).not_to be_empty

      folder = folders.first
      expect(folder).to be_a(KeeperSecretsManager::Dto::KeeperFolder)
      expect(folder.uid).not_to be_nil
      expect(folder.name).not_to be_nil
    end

    it 'creates FolderManager from retrieved folders' do
      folders = secrets_manager.get_folders
      folder_manager = KeeperSecretsManager::FolderManager.new(folders)

      expect(folder_manager).to be_a(KeeperSecretsManager::FolderManager)
      expect(folder_manager.instance_variable_get(:@folders)).to eq(folders)
    end

    it 'works with folder paths' do
      folders = secrets_manager.get_folders
      folder_manager = KeeperSecretsManager::FolderManager.new(folders)

      folders.each do |folder|
        path = folder_manager.get_folder_path(folder.uid)
        expect(path).not_to be_nil
        expect(path).to include(folder.name)
      end
    end
  end
end
