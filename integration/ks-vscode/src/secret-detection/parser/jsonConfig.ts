import { Position, Range, TextDocument } from 'vscode';
import { Parser } from './parser';
import { logger } from '../../utils/logger';
import { isSecretValue } from '../patterns/secretPatterns';

export default class JsonConfigParser extends Parser {
  public constructor(document: TextDocument) {
    super(document);
    logger.logDebug(
      `JsonConfigParser constructor called for document: ${document.fileName}`
    );
  }

  public parse(): void {
    logger.logDebug(
      `JsonConfigParser.parse starting for document: ${this.document.fileName}`
    );

    try {
      const text = this.document.getText();
      const json = JSON.parse(text);
      logger.logDebug(
        `JsonConfigParser: Successfully parsed JSON with ${Object.keys(json).length} top-level keys`
      );

      this.findSecretsInObject(json, '', 0);
    } catch (error) {
      logger.logDebug(
        `JsonConfigParser: Failed to parse JSON - ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      // Invalid JSON, skip parsing
    }

    logger.logDebug(
      `JsonConfigParser.parse completed for document: ${this.document.fileName}, found ${this.matches.length} secrets`
    );
  }

  private findSecretsInObject(
    obj: Record<string, unknown>,
    path: string,
    lineOffset: number
  ): void {
    logger.logDebug(
      `JsonConfigParser.findSecretsInObject: Processing path: ${path}, objectKeys: ${Object.keys(obj).length}`
    );

    for (const [key, value] of Object.entries(obj)) {
      const currentPath = path ? `${path}.${key}` : key;

      if (typeof value === 'string' && this.isSecret(value)) {
        logger.logDebug(
          `JsonConfigParser: Secret detected at path: ${currentPath}, valueLength: ${value.length}`
        );
        const range = this.findValueRange(key, value);
        if (range) {
          this.matches.push({ range, fieldValue: value });
          logger.logDebug(
            `JsonConfigParser: Added match for path: ${currentPath}`
          );
        } else {
          logger.logDebug(
            `JsonConfigParser: Failed to find range for path: ${currentPath}`
          );
        }
      } else if (typeof value === 'object' && value !== null) {
        this.findSecretsInObject(
          value as Record<string, unknown>,
          currentPath,
          lineOffset
        );
      }
    }
  }

  private isSecret(value: string): boolean {
    logger.logDebug(
      `JsonConfigParser.isSecretValue checking valueLength: ${value.length}`
    );

    // Skip if already a Keeper reference
    if (value.startsWith('keeper://')) {
      logger.logDebug(
        `JsonConfigParser.isSecretValue: Value is already a keeper reference`
      );
      return false;
    }

    // Use centralized pattern matching
    const result = isSecretValue(value);
    logger.logDebug(`JsonConfigParser.isSecretValue result: ${result}`);
    return result;
  }

  private findValueRange(key: string, value: string): Range | null {
    const text = this.document.getText();
    const lines = text.split('\n');

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];

      // Look for the key-value pair in this line
      const keyValuePattern = new RegExp(`"${key}"\\s*:\\s*"([^"]*)"`, 'g');
      let match;

      while ((match = keyValuePattern.exec(line)) !== null) {
        const matchedValue = match[1];

        // Check if this value matches our secret
        if (matchedValue === value) {
          // Find the start position of the value (after the colon and quotes)
          const valueStart = line.indexOf(`"${value}"`, match.index);
          if (valueStart !== -1) {
            // Add 1 to skip the opening quote
            const startPos = valueStart + 1;
            const endPos = startPos + value.length;

            return new Range(
              new Position(lineIndex, startPos),
              new Position(lineIndex, endPos)
            );
          }
        }
      }

      // Also check for unquoted values
      const unquotedPattern = new RegExp(`"${key}"\\s*:\\s*([^,\\s]+)`, 'g');
      while ((match = unquotedPattern.exec(line)) !== null) {
        const matchedValue = match[1];

        if (matchedValue === value) {
          const valueStart = match.index + match[0].indexOf(matchedValue);
          const endPos = valueStart + value.length;

          return new Range(
            new Position(lineIndex, valueStart),
            new Position(lineIndex, endPos)
          );
        }
      }
    }

    return null;
  }
}
