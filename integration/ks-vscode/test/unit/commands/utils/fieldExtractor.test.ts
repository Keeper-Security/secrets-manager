import { FieldExtractor } from '../../../../src/commands/utils/fieldExtractor';
import { KEEPER_NOTATION_FIELD_TYPES } from '../../../../src/utils/constants';

describe('Field Extractor', () => {
  describe('extractFieldValue', () => {
    it('should extract field values correctly', () => {
      const mockRecordDetails = {
        fields: [
          { label: 'username', type: 'login', value: ['admin'] },
          { label: 'password', type: 'password', value: ['secret123'] }
        ],
        custom: [
          { label: 'api_key', type: 'text', value: ['key123'] },
          { label: 'notes', type: 'note', value: ['Important note'] }
        ]
      };

      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'username')).toBe('admin');
      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'password')).toBe('secret123');
      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.CUSTOM_FIELD, 'api_key')).toBe('key123');
      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.CUSTOM_FIELD, 'notes')).toBe('Important note');
    });

    it('should handle missing fields gracefully', () => {
      const mockRecordDetails = {
        fields: [
          { label: 'username', type: 'login', value: ['admin'] }
        ],
        custom: []
      };

      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'nonexistent')).toBeNull();
      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.CUSTOM_FIELD, 'nonexistent')).toBeNull();
    });

    it('should handle invalid field structure gracefully', () => {
      const mockRecordDetails = {
        fields: 'invalid', // Should be an array
        custom: []
      };

      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'username')).toBeNull();
    });

    it('should handle empty field arrays', () => {
      const mockRecordDetails = {
        fields: [],
        custom: []
      };

      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'username')).toBeNull();
      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.CUSTOM_FIELD, 'api_key')).toBeNull();
    });

    it('should handle fields with empty values', () => {
      const mockRecordDetails = {
        fields: [
          { label: 'username', type: 'login', value: [''] },
          { label: 'password', type: 'password', value: ['secret123'] }
        ],
        custom: []
      };

      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'username')).toBe('');
      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'password')).toBe('secret123');
    });

    it('should handle malformed field data gracefully', () => {
      const mockRecordDetails = {
        fields: [
          { label: 'username', type: 'login', value: 'not-an-array' } // Should be array
        ],
        custom: []
      };

      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'username')).toBeNull();
    });

    it('should handle field value arrays with multiple values', () => {
      const mockRecordDetails = {
        fields: [
          { label: 'tags', type: 'text', value: ['tag1', 'tag2', 'tag3'] }
        ],
        custom: []
      };

      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'tags')).toBe('tag1tag2tag3');
    });

    it('should handle case-sensitive field matching', () => {
      const mockRecordDetails = {
        fields: [
          { label: 'UserName', type: 'login', value: ['admin'] },
          { label: 'username', type: 'login', value: ['user'] }
        ],
        custom: []
      };

      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'UserName')).toBe('admin');
      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'username')).toBe('user');
    });

    it('should handle type-based field matching', () => {
      const mockRecordDetails = {
        fields: [
          { label: 'username', type: 'login', value: ['admin'] },
          { label: 'username', type: 'text', value: ['user'] }
        ],
        custom: []
      };

      // Should find the first match (by label)
      expect(FieldExtractor.extractFieldValue(mockRecordDetails, KEEPER_NOTATION_FIELD_TYPES.FIELD, 'username')).toBe('admin');
    });
  });
}); 