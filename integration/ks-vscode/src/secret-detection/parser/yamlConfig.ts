import { Position, Range, TextDocument } from 'vscode';
import { Parser } from './parser';
import { logger } from '../../utils/logger';
import {
  isSecretValue,
  isSecretKey,
  isPlaceholder,
} from '../patterns/secretPatterns';

export default class YamlConfigParser extends Parser {
  public constructor(document: TextDocument) {
    super(document);
    logger.logDebug(
      `YamlConfigParser constructor called for document: ${this.document.fileName}`
    );
  }

  public parse(): void {
    logger.logDebug(
      `YamlConfigParser.parse starting for document: ${this.document.fileName}`
    );
    try {
      const text = this.document.getText();
      const lines = text.split('\n');
      logger.logDebug(`YamlConfigParser: Processing ${lines.length} lines`);

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];
        this.processYamlLine(line, lineIndex);
      }
    } catch (error) {
      logger.logDebug(
        `YamlConfigParser: Failed to parse YAML - ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      // Invalid YAML, skip parsing
    }

    logger.logDebug(
      `YamlConfigParser.parse completed for document: ${this.document.fileName}, found ${this.matches.length} secrets`
    );
  }

  private processYamlLine(line: string, lineIndex: number): void {
    // Skip comments and empty lines
    if (this.isCommentOrEmpty(line)) {
      return;
    }

    // Parse YAML key-value pairs
    const keyValueMatch = this.parseYamlKeyValue(line);
    if (keyValueMatch) {
      const { key, value, valueStart, valueEnd } = keyValueMatch;

      if (this.isSecret(key, value)) {
        logger.logDebug(
          `YamlConfigParser: Secret detected at line ${lineIndex + 1} - key: ${key}, valueLength: ${value.length}`
        );
        const range = new Range(
          new Position(lineIndex, valueStart),
          new Position(lineIndex, valueEnd)
        );

        this.matches.push({
          range,
          fieldValue: value,
        });
        logger.logDebug(
          `YamlConfigParser: Added match for line ${lineIndex + 1}`
        );
      }
    }
  }

  private parseYamlKeyValue(line: string): {
    key: string;
    value: string;
    keyStart: number;
    valueStart: number;
    valueEnd: number;
  } | null {
    // Handle different YAML value formats

    // 1. Array format: - KEY=value (for environment variables)
    const arrayMatch = line.match(/^(\s*)-\s*([^=]+)=(.+)$/);
    if (arrayMatch) {
      const [, indent, key, value] = arrayMatch;
      const cleanValue = value.trim();

      // Skip if value looks like a comment or is empty
      if (cleanValue.startsWith('#') || cleanValue === '') {
        return null;
      }

      const keyStart = indent.length + 2; // +2 for "- "
      const valueStart = line.indexOf(cleanValue);
      const valueEnd = valueStart + cleanValue.length;

      return {
        key: key.trim(),
        value: cleanValue,
        keyStart,
        valueStart,
        valueEnd,
      };
    }

    // 2. Quoted strings: key: "value"
    const quotedMatch = line.match(/^(\s*)([^:]+):\s*["']([^"']*)["']/);
    if (quotedMatch) {
      const [, indent, key, value] = quotedMatch;
      const keyStart = indent.length;
      const valueStart = line.indexOf(`"${value}"`);
      const valueEnd = valueStart + value.length;

      return {
        key: key.trim(),
        value,
        keyStart,
        valueStart,
        valueEnd,
      };
    }

    // 3. Unquoted strings: key: value
    const unquotedMatch = line.match(/^(\s*)([^:]+):\s*(.+)$/);
    if (unquotedMatch) {
      const [, indent, key, value] = unquotedMatch;
      const cleanValue = value.trim();

      // Skip if value looks like a comment or is empty
      if (cleanValue.startsWith('#') || cleanValue === '') {
        return null;
      }

      const keyStart = indent.length;
      const valueStart = line.indexOf(cleanValue);
      const valueEnd = valueStart + cleanValue.length;

      return {
        key: key.trim(),
        value: cleanValue,
        keyStart,
        valueStart,
        valueEnd,
      };
    }

    return null;
  }

  private isSecret(key: string, value: string): boolean {
    // Skip if already a Keeper reference
    if (value.startsWith('keeper://')) {
      return false;
    }

    // Skip if looks like a placeholder
    if (isPlaceholder(value)) {
      return false;
    }

    // Use centralized pattern matching
    const isSecretKeyMatch = isSecretKey(key);
    const isSecretValueMatch = isSecretValue(value);

    // Simple logic: if key OR value suggests secret, show CodeLens
    return isSecretKeyMatch || isSecretValueMatch;
  }

  private isCommentOrEmpty(line: string): boolean {
    return /^\s*#/.test(line) || /^\s*$/.test(line);
  }
}
