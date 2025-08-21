/* eslint-disable @typescript-eslint/no-explicit-any */
import { KEEPER_NOTATION_FIELD_TYPES } from '../../utils/constants';
import { logger } from '../../utils/logger';

export class FieldExtractor {
  static extractFieldValue(
    recordDetails: any,
    fieldType: KEEPER_NOTATION_FIELD_TYPES,
    itemName: string
  ): string | null {
    try {
      const fields =
        fieldType === KEEPER_NOTATION_FIELD_TYPES.CUSTOM_FIELD
          ? recordDetails.custom
          : recordDetails.fields;

      if (!Array.isArray(fields)) {
        logger.logError(
          `Invalid field structure for ${fieldType}: ${itemName}`
        );
        return null;
      }

      // Efficient search using find()
      const field = fields.find(
        (f: any) => f.label === itemName || f.type === itemName
      );

      if (!field) {
        logger.logError(`Field not found: ${itemName} in ${fieldType}`);
        return null;
      }

      if (!Array.isArray(field.value)) {
        logger.logError(`Invalid field value structure for ${itemName}`);
        return null;
      }

      return field.value.join('');
    } catch (error) {
      logger.logError(`Error extracting field value for ${itemName}:`, error);
      return null;
    }
  }
}
