import { Position, Range, TextDocument } from 'vscode';
import { Parser } from './parser';
import { logger } from '../../utils/logger';
import { DOTENV_LINE } from '../../utils/constants';
import {
  isSecretValue,
  isSecretKey,
  isPlaceholder,
} from '../patterns/secretPatterns';

export default class DotEnvParser extends Parser {
  public constructor(document: TextDocument) {
    super(document);
    logger.logDebug(
      `DotEnvParser constructor called for document: ${document.fileName}`
    );
  }

  public parse(): void {
    logger.logDebug(
      `DotEnvParser.parse starting for document: ${this.document.fileName}`
    );

    for (
      let lineNumber = 0;
      lineNumber < this.document.lineCount;
      lineNumber++
    ) {
      const lineValue = this.document.lineAt(lineNumber).text;
      const match = DOTENV_LINE.exec(lineValue);

      if (!match) {
        continue;
      }

      const keyValue = match[1];
      // Default nullish to empty string
      let fieldValue = match[2] || '';
      // Remove whitespace
      fieldValue = fieldValue.trim();
      // Remove surrounding quotes
      fieldValue = fieldValue.replace(/^(["'`])([\S\s]*)\1$/gm, '$2');

      if (fieldValue.length === 0 || fieldValue.startsWith('keeper://')) {
        logger.logDebug(
          `DotEnvParser: Skipping line ${lineNumber + 1} - empty value or keeper reference`
        );
        continue;
      }

      // Check if it's a secret
      if (this.isSecret(keyValue, fieldValue)) {
        logger.logDebug(
          `DotEnvParser: Secret detected at line ${lineNumber + 1} - key: ${keyValue}, valueLength: ${fieldValue.length}`
        );
        const index = lineValue.indexOf(fieldValue);
        const range = new Range(
          new Position(lineNumber, index),
          new Position(lineNumber, index + fieldValue.length)
        );

        this.matches.push({ range, fieldValue });
      }
    }

    logger.logDebug(
      `DotEnvParser.parse completed for document: ${this.document.fileName}, found ${this.matches.length} secrets`
    );
  }

  private isSecret(key: string, value: string): boolean {
    logger.logDebug(
      `DotEnvParser.isSecret checking - key: ${key}, valueLength: ${value.length}`
    );

    // Skip if looks like a placeholder
    if (isPlaceholder(value)) {
      logger.logDebug(`DotEnvParser.isSecret: Value appears to be placeholder`);
      return false;
    }

    // Use centralized pattern matching
    const isSecretKeyMatch = isSecretKey(key);
    const isSecretValueMatch = isSecretValue(value);

    // Simple logic: if key OR value suggests secret, show CodeLens
    const result = isSecretKeyMatch || isSecretValueMatch;
    logger.logDebug(
      `DotEnvParser.isSecret result: ${result} (key suggests secret: ${isSecretKeyMatch}, value suggests secret: ${isSecretValueMatch})`
    );

    return result;
  }
}
