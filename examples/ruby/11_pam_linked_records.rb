#!/usr/bin/env ruby

# PAM Linked Records Example - Working with PAM resources and linked credentials
# Shows how to retrieve PAM resources and their linked admin/launch credentials

require 'keeper_secrets_manager'

# Initialize from saved configuration file
secrets_manager = KeeperSecretsManager.from_file('keeper_config.json')

puts '=== PAM Linked Records Example ==='

# 1. Retrieve records with linked records enabled
puts "\n1. Retrieving PAM resources with linked credentials..."
begin
  # Enable request_links to fetch linked records
  query_options = KeeperSecretsManager::Dto::QueryOptions.new(request_links: true)
  records = secrets_manager.get_secrets([], query_options)

  # Find PAM resources (types starting with 'pam')
  pam_resources = records.select { |r| r.type.start_with?('pam') }

  if pam_resources.empty?
    puts 'No PAM resources found in your vault.'
    puts "\nPAM resource types include:"
    puts "  - pamMachine (servers, VMs)"
    puts "  - pamDatabase (database servers)"
    puts "  - pamDirectory (LDAP, AD)"
    puts "  - pamUser (user accounts)"
    exit
  end

  puts "✓ Found #{pam_resources.length} PAM resource(s)"
rescue StandardError => e
  puts "Error: #{e.message}"
  exit 1
end

# 2. Display PAM resources and their metadata
puts "\n2. PAM Resources and Metadata:"
pam_resources.each_with_index do |resource, index|
  puts "\n[#{index + 1}] #{resource.title}"
  puts "    Type: #{resource.type}"
  puts "    UID: #{resource.uid}"
  puts "    Editable: #{resource.is_editable ? 'Yes' : 'No'}"
  puts "    Folder: #{resource.inner_folder_uid}" if resource.inner_folder_uid

  # Show linked credentials count
  link_count = resource.links ? resource.links.length : 0
  puts "    Linked Credentials: #{link_count}"
end

# 3. Explore linked credentials
puts "\n3. Linked Credentials Details:"
pam_resources.each do |resource|
  puts "\n#{resource.title}:"

  if resource.links && !resource.links.empty?
    resource.links.each do |link|
      link_uid = link['recordUid']
      link_path = link['path']

      # Retrieve the linked credential record
      begin
        linked_records = secrets_manager.get_secrets([link_uid])
        linked_record = linked_records.first

        puts "  [#{link_path}] #{linked_record.title}"
        puts "    UID: #{linked_record.uid}"
        puts "    Type: #{linked_record.type}"
        puts "    Username: #{linked_record.login}" if linked_record.login
        puts "    Password: #{linked_record.password ? '***' : '(none)'}"
      rescue StandardError => e
        puts "  [#{link_path}] Error retrieving: #{e.message}"
      end
    end
  else
    puts '  (No linked credentials)'
  end
end

# 4. Example: Find admin credentials for a specific PAM machine
puts "\n4. Example: Finding Admin Credentials for PAM Machine"
pam_machine = pam_resources.find { |r| r.type == 'pamMachine' }

if pam_machine
  puts "\nMachine: #{pam_machine.title}"

  if pam_machine.links
    # Find admin credential link
    admin_link = pam_machine.links.find { |link| link['path'] == 'admin' }

    if admin_link
      admin_records = secrets_manager.get_secrets([admin_link['recordUid']])
      admin_credential = admin_records.first

      puts '✓ Admin Credentials Found:'
      puts "  Username: #{admin_credential.login}"
      puts "  Password: #{admin_credential.password ? '***' : '(none)'}"
      puts '  (Password hidden for security)'
    else
      puts '  (No admin credentials linked)'
    end

    # Find launch credential link
    launch_link = pam_machine.links.find { |link| link['path'] == 'launch' }

    if launch_link
      launch_records = secrets_manager.get_secrets([launch_link['recordUid']])
      launch_credential = launch_records.first

      puts '✓ Launch Credentials Found:'
      puts "  Username: #{launch_credential.login}"
      puts "  Password: #{launch_credential.password ? '***' : '(none)'}"
    end
  else
    puts '  (No credentials linked to this machine)'
  end
else
  puts "\nNo PAM machines found. Example works with:"
  puts '  - pamMachine resources'
  puts '  - Linked admin credentials'
  puts '  - Linked launch credentials'
end

# 5. Use Case Examples
puts "\n=== Use Cases ==="
puts "\n1. Automated Server Access:"
puts "   - Retrieve PAM machine and admin credentials"
puts "   - Connect to server with retrieved credentials"
puts "   - Perform maintenance/deployment tasks"
puts "   - Audit access in Keeper logs"

puts "\n2. Database Connection Management:"
puts "   - Find pamDatabase resource by name"
puts "   - Retrieve linked admin credentials"
puts "   - Build connection string dynamically"
puts "   - Rotate credentials programmatically"

puts "\n3. Zero-Trust Access Patterns:"
puts "   - Separate resource definitions from credentials"
puts "   - Credentials not embedded in resources"
puts "   - Centralized credential management"
puts "   - Fine-grained access control"

puts "\n4. Credential Auditing:"
puts "   - List all PAM resources"
puts "   - Show which credentials are linked to which resources"
puts "   - Identify orphaned credentials"
puts "   - Track credential usage across resources"

# 6. Link Path Reference
puts "\n=== Link Path Reference ==="
puts "\nCommon link paths:"
puts "  'admin'  - Administrative credentials (full access)"
puts "  'launch' - Launch credentials (limited access)"
puts "  'custom' - Custom credential types"

puts "\nLink paths indicate the credential's role:"
puts "  - Admin: Full administrative access"
puts "  - Launch: User-level access for specific tasks"

# Tips
puts "\n=== Tips ==="
puts '- Always use request_links: true to retrieve linked records'
puts '- Check is_editable before attempting to modify PAM resources'
puts '- Link paths indicate credential types (admin, launch, etc.)'
puts '- Use inner_folder_uid to organize PAM resources'
puts '- Linked credentials are separate records with their own UIDs'
puts '- GraphSync technology enables efficient link retrieval'

puts "\n=== Performance Notes ==="
puts '- Requesting links increases response size and processing time'
puts '- Only enable request_links when you need linked credentials'
puts '- Consider caching PAM resources for repeated access'
puts '- Use UID-based retrieval for better performance'
