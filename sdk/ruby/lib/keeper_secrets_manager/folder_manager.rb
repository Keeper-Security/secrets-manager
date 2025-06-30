module KeeperSecretsManager
  class FolderManager
    def initialize(folders)
      @folders = folders
    end
    
    # Build a hierarchical tree structure from flat folder list
    def build_folder_tree
      # Create a hash for quick lookup
      folder_map = {}
      @folders.each { |f| folder_map[f.uid] = f }
      
      # Find root folders (no parent) and build tree
      root_folders = []
      @folders.each do |folder|
        if folder.parent_uid.nil? || folder.parent_uid.empty?
          root_folders << build_node(folder, folder_map)
        end
      end
      
      root_folders
    end
    
    # Get folder path from root to given folder
    def get_folder_path(folder_uid)
      folder = @folders.find { |f| f.uid == folder_uid }
      return nil unless folder
      
      path = []
      current = folder
      
      # Walk up the tree
      while current
        path.unshift(current.name)
        current = @folders.find { |f| f.uid == current.parent_uid }
      end
      
      path.join('/')
    end
    
    # Get all ancestors of a folder (parent, grandparent, etc.)
    def get_ancestors(folder_uid)
      ancestors = []
      folder = @folders.find { |f| f.uid == folder_uid }
      return ancestors unless folder
      
      current_parent_uid = folder.parent_uid
      while current_parent_uid && !current_parent_uid.empty?
        parent = @folders.find { |f| f.uid == current_parent_uid }
        break unless parent
        
        ancestors << parent
        current_parent_uid = parent.parent_uid
      end
      
      ancestors
    end
    
    # Get all descendants of a folder (children, grandchildren, etc.)
    def get_descendants(folder_uid)
      descendants = []
      children = @folders.select { |f| f.parent_uid == folder_uid }
      
      children.each do |child|
        descendants << child
        descendants.concat(get_descendants(child.uid))
      end
      
      descendants
    end
    
    # Find folder by name (optionally within a parent)
    def find_folder_by_name(name, parent_uid: nil)
      if parent_uid
        @folders.find { |f| f.name == name && f.parent_uid == parent_uid }
      else
        @folders.find { |f| f.name == name }
      end
    end
    
    # Print folder tree to console
    def print_tree(folders = nil, indent = 0)
      folders ||= build_folder_tree
      
      folders.each do |node|
        puts "#{' ' * indent}├── #{node[:folder].name} (#{node[:folder].uid})"
        if node[:folder].records && !node[:folder].records.empty?
          node[:folder].records.each do |record|
            puts "#{' ' * (indent + 4)}└─ #{record.title} (#{record.uid})"
          end
        end
        print_tree(node[:children], indent + 4) if node[:children]
      end
    end
    
    private
    
    def build_node(folder, folder_map)
      node = { 
        folder: folder,
        children: []
      }
      
      # Find children
      @folders.each do |f|
        if f.parent_uid == folder.uid
          node[:children] << build_node(f, folder_map)
        end
      end
      
      node
    end
  end
end