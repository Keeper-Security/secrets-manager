# Enhanced notation functionality for files and TOTP

module KeeperSecretsManager
  module Notation
    class Parser
      # Get value with enhanced functionality
      # This method extends the basic parse method to handle special cases
      def get_value(notation, options = {})
        value = parse(notation)
        
        # Check if we should process special types
        return value unless options[:auto_process]
        
        # Parse the notation to understand what we're dealing with
        parsed = parse_notation(notation)
        return value if parsed.length < 3
        
        selector = parsed[2].text&.first
        return value unless selector
        
        case selector.downcase
        when 'file'
          # If it's a file and auto_download is enabled, download it
          if options[:auto_download] && value.is_a?(Hash) && value['fileUid']
            begin
              file_data = @secrets_manager.download_file(value['fileUid'])
              return file_data['data']  # Return file content
            rescue => e
              raise NotationError, "Failed to download file: #{e.message}"
            end
          end
          
        when 'field'
          # Check if it's a TOTP field
          parameter = parsed[2].parameter&.first
          if parameter && parameter.downcase == 'onetimecode' && value.is_a?(String) && value.start_with?('otpauth://')
            if options[:generate_totp_code]
              begin
                totp_params = TOTP.parse_url(value)
                return TOTP.generate_code(
                  totp_params['secret'],
                  algorithm: totp_params['algorithm'],
                  digits: totp_params['digits'],
                  period: totp_params['period']
                )
              rescue => e
                raise NotationError, "Failed to generate TOTP code: #{e.message}"
              end
            end
          end
        end
        
        value
      end
      
      # Convenience method to get TOTP code directly
      def get_totp_code(notation)
        get_value(notation, auto_process: true, generate_totp_code: true)
      end
      
      # Convenience method to download file content directly
      def download_file(notation)
        get_value(notation, auto_process: true, auto_download: true)
      end
    end
  end
end