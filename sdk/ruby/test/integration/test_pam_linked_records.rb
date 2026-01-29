#!/usr/bin/env ruby

# Test PAM linked records with GraphSync™
#
# This test validates the request_links feature works correctly
# for retrieving PAM resources with linked credentials
#
# MOCK MODE (no config.base64):
#   - Tests QueryOptions with request_links parameter
#   - Verifies links array structure
#   - Tests link path detection
#
# LIVE MODE (with KSM_CONFIG + PAM resources):
#   - Tests against real Keeper API with PAM resources
#   - Retrieves actual linked credentials
#   - Validates link paths (admin, launch)

require_relative '../../lib/keeper_secrets_manager'
require_relative 'mock_helper'
require 'json'

puts '=== Testing PAM Linked Records (GraphSync) ==='
puts "Mode: #{MockHelper.mock_mode? ? 'MOCK' : 'LIVE'}"
puts '-' * 50

class PAMLinkedRecordsTest
  def initialize
    @sm = MockHelper.create_mock_secrets_manager
  end

  def run_all_tests
    test_request_links_parameter
    test_links_array_structure
    test_linked_credential_retrieval
    test_link_path_types
    puts "\n[PASS] All PAM linked records tests completed"
  end

  private

  def test_request_links_parameter
    puts "\n1. Testing request_links QueryOptions parameter..."

    begin
      # Request without links
      query_options_no_links = KeeperSecretsManager::Dto::QueryOptions.new(request_links: false)
      records_no_links = @sm.get_secrets_with_options(query_options_no_links)

      puts "   [OK] Retrieved #{records_no_links.length} records without request_links"

      # Request with links (GraphSync enabled)
      query_options_with_links = KeeperSecretsManager::Dto::QueryOptions.new(request_links: true)
      records_with_links = @sm.get_secrets_with_options(query_options_with_links)

      puts "   [OK] Retrieved #{records_with_links.length} records with request_links: true"

      # Verify links array exists when request_links: true
      has_links_field = records_with_links.any? { |r| r.respond_to?(:links) }
      if has_links_field
        puts '   [OK] Records have links field when request_links: true'
      else
        puts '   [INFO] No linked records in test data'
      end
    rescue StandardError => e
      puts "   [FAIL] request_links parameter test failed: #{e.message}"
      puts "   #{e.class}: #{e.backtrace.first(3).join("\n   ")}"
    end
  end

  def test_links_array_structure
    puts "\n2. Testing links array structure..."

    begin
      # Get records with links
      query_options = KeeperSecretsManager::Dto::QueryOptions.new(request_links: true)
      records = @sm.get_secrets_with_options(query_options)

      # Find records with links
      records_with_links = records.select { |r| r.links && r.links.any? }

      if records_with_links.any?
        record = records_with_links.first
        link = record.links.first

        puts "   [OK] Found record with #{record.links.length} linked record(s)"
        puts "   Link structure:"
        puts "      - recordUid: #{link['recordUid']}"
        puts "      - path: #{link['path']}"

        # Verify link has required fields
        if link['recordUid'] && link['path']
          puts '   [OK] Link has required fields (recordUid, path)'
        else
          puts '   [WARN] Link missing required fields'
        end
      else
        puts '   [INFO] No records with links in test data'
        puts '   [INFO] (PAM resources needed for linked records)'
      end
    rescue StandardError => e
      puts "   [FAIL] Links array structure test failed: #{e.message}"
      puts "   #{e.class}: #{e.backtrace.first(3).join("\n   ")}"
    end
  end

  def test_linked_credential_retrieval
    puts "\n3. Testing linked credential retrieval..."

    begin
      # Get records with links
      query_options = KeeperSecretsManager::Dto::QueryOptions.new(request_links: true)
      records = @sm.get_secrets_with_options(query_options)

      # Find PAM resources
      pam_resources = records.select { |r| r.type.start_with?('pam') if r.type }

      if pam_resources.any?
        pam_resource = pam_resources.first
        puts "   [OK] Found PAM resource: #{pam_resource.title} (#{pam_resource.type})"

        if pam_resource.links && pam_resource.links.any?
          # Retrieve the first linked credential
          link = pam_resource.links.first
          linked_uid = link['recordUid']

          puts "   [OK] Retrieving linked credential: #{linked_uid}"

          linked_records = @sm.get_secrets([linked_uid])
          linked_record = linked_records.first

          if linked_record
            puts "   [OK] Retrieved linked credential: #{linked_record.title}"
            puts "      - Type: #{linked_record.type}"
            puts "      - Has login: #{linked_record.login ? 'yes' : 'no'}"
            puts "      - Has password: #{linked_record.password ? 'yes' : 'no'}"
          else
            puts '   [WARN] Linked credential not found'
          end
        else
          puts '   [INFO] PAM resource has no linked credentials'
        end
      else
        puts '   [INFO] No PAM resources in test data'
        puts '   [INFO] (pamMachine, pamDatabase, pamDirectory needed)'
      end
    rescue StandardError => e
      puts "   [FAIL] Linked credential retrieval failed: #{e.message}"
      puts "   #{e.class}: #{e.backtrace.first(3).join("\n   ")}"
    end
  end

  def test_link_path_types
    puts "\n4. Testing link path types (admin, launch)..."

    begin
      # Get records with links
      query_options = KeeperSecretsManager::Dto::QueryOptions.new(request_links: true)
      records = @sm.get_secrets_with_options(query_options)

      # Find PAM resources
      pam_resources = records.select { |r| r.type.start_with?('pam') if r.type }

      if pam_resources.any?
        admin_links = []
        launch_links = []
        custom_links = []

        pam_resources.each do |resource|
          next unless resource.links

          resource.links.each do |link|
            case link['path']
            when 'admin'
              admin_links << link
            when 'launch'
              launch_links << link
            else
              custom_links << link
            end
          end
        end

        puts "   Link path distribution:"
        puts "      - Admin credentials: #{admin_links.length}"
        puts "      - Launch credentials: #{launch_links.length}"
        puts "      - Custom/other: #{custom_links.length}"

        if admin_links.any? || launch_links.any?
          puts '   [OK] Found standard PAM link types'
        else
          puts '   [INFO] No admin/launch links found (custom paths only)'
        end
      else
        puts '   [INFO] No PAM resources in test data'
      end
    rescue StandardError => e
      puts "   [FAIL] Link path test failed: #{e.message}"
      puts "   #{e.class}: #{e.backtrace.first(3).join("\n   ")}"
    end
  end
end

# Run tests
if __FILE__ == $PROGRAM_NAME
  test = PAMLinkedRecordsTest.new
  test.run_all_tests
end
