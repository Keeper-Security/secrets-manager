require 'base64'

module KeeperSecretsManager
  module Notation
    # Parse and resolve keeper:// notation URIs
    class Parser
      ESCAPE_CHAR = '\\'.freeze
      ESCAPE_CHARS = '/[]\\'.freeze # Characters that can be escaped

      def initialize(secrets_manager)
        @secrets_manager = secrets_manager
      end

      # Parse notation and return value
      def parse(notation)
        return nil if notation.nil? || notation.empty?

        # Validate notation format before parsing
        raise NotationError, 'Invalid notation format: must be a string' unless notation.is_a?(String)

        # Parse notation URI
        begin
          parsed = parse_notation(notation)
        rescue StandardError => e
          raise NotationError, "Invalid notation format: #{e.message}"
        end

        # Validate we have minimum required sections
        raise NotationError, "Invalid notation: #{notation}" if parsed.length < 3

        # Extract components
        record_token = parsed[1].text&.first
        selector = parsed[2].text&.first

        raise NotationError, 'Invalid notation: missing record' unless record_token
        raise NotationError, 'Invalid notation: missing selector' unless selector

        # Get record
        records = @secrets_manager.get_secrets([record_token])

        # If not found by UID, try by title
        if records.empty?
          all_records = @secrets_manager.get_secrets
          records = all_records.select { |r| r.title == record_token }
        end

        raise NotationError, "Multiple records match '#{record_token}'" if records.size > 1
        raise NotationError, "No records match '#{record_token}'" if records.empty?

        record = records.first

        # Extract parameters
        parameter = parsed[2].parameter&.first
        index1 = parsed[2].index1&.first
        index2 = parsed[2].index2&.first

        # Process selector
        case selector.downcase
        when 'type'
          record.type
        when 'title'
          record.title
        when 'notes'
          record.notes
        when 'file'
          handle_file_selector(record, parameter, record_token)
        when 'field', 'custom_field'
          handle_field_selector(record, selector, parameter, index1, index2, parsed[2])
        else
          raise NotationError, "Invalid selector: #{selector}"
        end
      end

      private

      # Handle file selector
      def handle_file_selector(record, parameter, record_token)
        raise NotationError, 'Missing required parameter: filename or file UID' unless parameter

        if record.files.nil? || record.files.empty?
          raise NotationError,
                "Record #{record_token} has no file attachments"
        end

        # Find matching file
        files = record.files.select do |f|
          parameter == f.name || parameter == f.title || parameter == f.uid
        end

        raise NotationError, "No files match '#{parameter}'" if files.empty?
        raise NotationError, "Multiple files match '#{parameter}'" if files.size > 1

        # Return file object (downloading would be handled by the caller)
        files.first
      end

      # Handle field selector
      def handle_field_selector(record, selector, parameter, index1, index2, parsed_section)
        raise NotationError, 'Missing required parameter for field' unless parameter

        # Get field array
        custom_field = selector.downcase == 'custom_field'
        field = record.get_field(parameter, custom_field)

        raise NotationError, "Field '#{parameter}' not found" unless field

        # Get field values
        values = field['value'] || []

        # Handle index1
        idx = parse_index(index1)

        # If index1 is not a valid number but has a value, treat it as a property name
        if idx == -1 && index1 && !index1.empty?
          # index1 is a property name (e.g., [hostName])
          if values.first.is_a?(Hash)
            property = index1
            if values.first.key?(property)
              return values.first[property]
            else
              raise NotationError, "Property '#{property}' not found"
            end
          else
            raise NotationError, 'Cannot extract property from non-object value'
          end
        end

        raise NotationError, "Field index out of bounds: #{idx} >= #{values.size}" if idx >= values.size

        # Apply index1
        values = [values[idx]] if idx >= 0

        # Handle legacy compatibility
        return values.first if parsed_section.index1.nil? && parsed_section.index2.nil?

        if parsed_section.index1 && parsed_section.index1[1] == '[]' &&
           (index2.nil? || index2.empty?)
          return values
        end

        return values.first[index2] if index1.to_s.empty? && !index2.to_s.empty? && values.first.is_a?(Hash)

        # Handle index2 (property access)
        full_obj_value = parsed_section.index2.nil? ||
                         parsed_section.index2[1] == '' ||
                         parsed_section.index2[1] == '[]'

        if full_obj_value
          idx >= 0 ? values.first : values
        elsif values.first.is_a?(Hash)
          obj_property = index2
          if values.first.key?(obj_property)
            values.first[obj_property]
          else
            raise NotationError, "Property '#{obj_property}' not found"
          end
        else
          raise NotationError, 'Cannot extract property from non-object value'
        end
      end

      # Parse index value
      def parse_index(index_str)
        return -1 if index_str.nil? || index_str.empty?

        begin
          Integer(index_str)
        rescue ArgumentError
          -1
        end
      end

      # Parse notation URI into sections
      def parse_notation(notation)
        # Handle base64 encoded notation
        unless notation.include?('/')
          begin
            decoded = Base64.urlsafe_decode64(notation)
            notation = decoded.force_encoding('UTF-8')
          rescue StandardError
            raise NotationError, 'Invalid notation format'
          end
        end

        # Parse sections
        prefix = parse_section(notation, 'prefix', 0)
        pos = prefix.present? ? prefix.end_pos + 1 : 0

        record = parse_section(notation, 'record', pos)
        pos = record.present? ? record.end_pos + 1 : notation.length

        selector = parse_section(notation, 'selector', pos)
        pos = selector.present? ? selector.end_pos + 1 : notation.length

        footer = parse_section(notation, 'footer', pos)

        [prefix, record, selector, footer]
      end

      # Parse a section of the notation
      def parse_section(notation, section_name, pos)
        result = NotationSection.new(section_name)
        result.start_pos = pos

        case section_name.downcase
        when 'prefix'
          # Check for keeper:// prefix
          prefix = "#{Core::SecretsManager::NOTATION_PREFIX}://"
          if notation.downcase.start_with?(prefix.downcase)
            result.present = true
            result.start_pos = 0
            result.end_pos = prefix.length - 1
            result.text = [notation[0...prefix.length], notation[0...prefix.length]]
          end

        when 'footer'
          # Footer is anything after the last section
          if pos < notation.length
            result.present = true
            result.start_pos = pos
            result.end_pos = notation.length - 1
            result.text = [notation[pos..], notation[pos..]]
          end

        when 'record'
          # Record is required - parse until '/' with escaping
          if pos < notation.length
            parsed = parse_subsection(notation, pos, '/', true)
            if parsed
              result.present = true
              result.start_pos = pos
              result.end_pos = pos + parsed[1].length - 1
              result.text = parsed
            end
          end

        when 'selector'
          # Selector is required
          if pos < notation.length
            parsed = parse_subsection(notation, pos, '/', false)
            if parsed
              result.present = true
              result.start_pos = pos
              result.end_pos = pos + parsed[1].length - 1
              result.text = parsed

              # Check for long selectors that have parameters
              if %w[field custom_field file].include?(parsed[0].downcase)
                # Parse parameter (field type/label or filename)
                param_parsed = parse_subsection(notation, result.end_pos + 1, '[', true)
                if param_parsed
                  result.parameter = param_parsed
                  plen = param_parsed[1].length
                  plen -= 1 if param_parsed[1].end_with?('[') && !param_parsed[1].end_with?('\\[')
                  result.end_pos += plen

                  # Parse index1 [N] or []
                  index1_parsed = parse_subsection(notation, result.end_pos + 1, '[]', true)
                  if index1_parsed
                    result.index1 = index1_parsed
                    result.end_pos += index1_parsed[1].length

                    # Parse index2 [property]
                    index2_parsed = parse_subsection(notation, result.end_pos + 1, '[]', true)
                    if index2_parsed
                      result.index2 = index2_parsed
                      result.end_pos += index2_parsed[1].length
                    end
                  end
                end
              end
            end
          end

        else
          raise NotationError, "Unknown section: #{section_name}"
        end

        result
      end

      # Parse subsection with delimiters and escaping
      def parse_subsection(text, pos, delimiters, escaped = false)
        return nil if text.nil? || text.empty? || pos < 0 || pos >= text.length

        raise NotationError, 'Internal error: incorrect delimiters' if delimiters.nil? || delimiters.length > 2

        token = ''
        raw = ''

        while pos < text.length
          if escaped && text[pos] == ESCAPE_CHAR
            # Handle escape sequence
            if pos + 1 >= text.length || !ESCAPE_CHARS.include?(text[pos + 1])
              raise NotationError, "Incorrect escape sequence at position #{pos}"
            end

            token += text[pos + 1]
            raw += text[pos, 2]
            pos += 2
          else
            raw += text[pos]

            if delimiters.length == 1
              # Single delimiter
              break if text[pos] == delimiters[0]

              token += text[pos]
            else
              # Two delimiters (for brackets)
              raise NotationError, "Index sections must start with '['" if raw[0] != delimiters[0]

              if raw.length > 1 && text[pos] == delimiters[0]
                raise NotationError, "Index sections do not allow extra '[' inside"
              end

              if !delimiters.include?(text[pos])
                token += text[pos]
              elsif text[pos] == delimiters[1]
                break
              end
            end

            pos += 1
          end
        end

        # Validate brackets are properly closed
        if delimiters.length == 2
          if raw.length < 2 || raw[0] != delimiters[0] || raw[-1] != delimiters[1]
            raise NotationError, "Index sections must be enclosed in '[' and ']'"
          end

          raise NotationError, "Index sections must be enclosed in '[' and ']'" if escaped && raw[-2] == ESCAPE_CHAR
        end

        [token, raw]
      end

      # Notation section data class
      class NotationSection
        attr_accessor :section, :present, :start_pos, :end_pos,
                      :text, :parameter, :index1, :index2

        def initialize(section_name)
          @section = section_name
          @present = false
          @start_pos = -1
          @end_pos = -1
          @text = nil
          @parameter = nil
          @index1 = nil
          @index2 = nil
        end

        def present?
          @present
        end
      end
    end
  end
end
