require 'spec_helper'
require 'keeper_secrets_manager/folder_manager'

RSpec.describe KeeperSecretsManager::FolderManager do
  let(:folders) do
    [
      # Root folders
      KeeperSecretsManager::Dto::KeeperFolder.new(
        'folderUid' => 'root1',
        'name' => 'Personal',
        'parent_uid' => nil
      ),
      KeeperSecretsManager::Dto::KeeperFolder.new(
        'folderUid' => 'root2',
        'name' => 'Work',
        'parent_uid' => nil
      ),
      # Child folders
      KeeperSecretsManager::Dto::KeeperFolder.new(
        'folderUid' => 'child1',
        'name' => 'Finance',
        'parent_uid' => 'root1'
      ),
      KeeperSecretsManager::Dto::KeeperFolder.new(
        'folderUid' => 'child2',
        'name' => 'Projects',
        'parent_uid' => 'root2'
      ),
      # Grandchild folder
      KeeperSecretsManager::Dto::KeeperFolder.new(
        'folderUid' => 'grandchild1',
        'name' => 'Banking',
        'parent_uid' => 'child1'
      )
    ]
  end
  
  subject { described_class.new(folders) }
  
  describe '#build_folder_tree' do
    it 'builds hierarchical tree structure' do
      tree = subject.build_folder_tree
      
      expect(tree.length).to eq(2) # Two root folders
      expect(tree[0][:folder].name).to eq('Personal')
      expect(tree[0][:children].length).to eq(1)
      expect(tree[0][:children][0][:folder].name).to eq('Finance')
      expect(tree[0][:children][0][:children].length).to eq(1)
      expect(tree[0][:children][0][:children][0][:folder].name).to eq('Banking')
    end
  end
  
  describe '#get_folder_path' do
    it 'returns full path from root to folder' do
      expect(subject.get_folder_path('grandchild1')).to eq('Personal/Finance/Banking')
      expect(subject.get_folder_path('child1')).to eq('Personal/Finance')
      expect(subject.get_folder_path('root1')).to eq('Personal')
    end
    
    it 'returns nil for non-existent folder' do
      expect(subject.get_folder_path('invalid')).to be_nil
    end
  end
  
  describe '#get_ancestors' do
    it 'returns all ancestors of a folder' do
      ancestors = subject.get_ancestors('grandchild1')
      expect(ancestors.length).to eq(2)
      expect(ancestors[0].uid).to eq('child1')
      expect(ancestors[1].uid).to eq('root1')
    end
    
    it 'returns empty array for root folder' do
      expect(subject.get_ancestors('root1')).to eq([])
    end
  end
  
  describe '#get_descendants' do
    it 'returns all descendants of a folder' do
      descendants = subject.get_descendants('root1')
      expect(descendants.length).to eq(2)
      expect(descendants.map(&:uid)).to include('child1', 'grandchild1')
    end
    
    it 'returns empty array for leaf folder' do
      expect(subject.get_descendants('grandchild1')).to eq([])
    end
  end
  
  describe '#find_folder_by_name' do
    it 'finds folder by name' do
      folder = subject.find_folder_by_name('Finance')
      expect(folder).not_to be_nil
      expect(folder.uid).to eq('child1')
    end
    
    it 'finds folder by name within parent' do
      # Add duplicate name in different parent
      folders << KeeperSecretsManager::Dto::KeeperFolder.new(
        'folderUid' => 'dup1',
        'name' => 'Finance',
        'parent_uid' => 'root2'
      )
      
      folder = subject.find_folder_by_name('Finance', parent_uid: 'root2')
      expect(folder.uid).to eq('dup1')
    end
    
    it 'returns nil for non-existent folder' do
      expect(subject.find_folder_by_name('NonExistent')).to be_nil
    end
  end
end