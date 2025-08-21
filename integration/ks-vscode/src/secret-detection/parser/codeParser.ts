import { Position, Range, TextDocument } from 'vscode';
import { Parser } from './parser';
import { logger } from '../../utils/logger';
import {
  isSecretValue,
  isSecretKey,
  isPlaceholder,
} from '../patterns/secretPatterns';

export default class CodeParser extends Parser {
  public constructor(document: TextDocument) {
    super(document);
    logger.logDebug(
      `CodeParser constructor called for document: ${this.document.fileName}`
    );
  }

  public parse(): void {
    logger.logDebug(
      `CodeParser.parse starting for document: ${this.document.fileName}`
    );

    try {
      const text = this.document.getText();
      const lines = text.split('\n');
      logger.logDebug(`CodeParser: Processing ${lines.length} lines`);

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];
        this.processCodeLine(line, lineIndex);
      }
    } catch (error) {
      logger.logDebug(
        `CodeParser: Failed to parse code - ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      // Invalid code, skip parsing
    }

    logger.logDebug(
      `CodeParser.parse completed for document: ${this.document.fileName}, found ${this.matches.length} secrets`
    );
  }

  private processCodeLine(line: string, lineIndex: number): void {
    // Skip comments and empty lines
    if (this.isCommentOrEmpty(line)) {
      return;
    }

    // Find assignments (only one per line)
    const assignment = this.findAssignment(line);

    if (assignment && this.isSecret(assignment.key, assignment.value)) {
      logger.logDebug(
        `CodeParser: Secret detected at line ${lineIndex + 1} - key: ${assignment.key}, valueLength: ${assignment.value.length}`
      );
      const range = new Range(
        new Position(lineIndex, assignment.valueStart),
        new Position(lineIndex, assignment.valueEnd)
      );

      this.matches.push({
        range,
        fieldValue: assignment.value,
      });
      logger.logDebug(`CodeParser: Added match for line ${lineIndex + 1}`);
    }
  }

  private findAssignment(line: string): {
    key: string;
    value: string;
    valueStart: number;
    valueEnd: number;
  } | null {
    // Try different patterns in order of specificity

    // 1. Variable assignments: const/let/var key = "value"
    const varPattern =
      /(?:const|let|var)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["']([^"']+)["']/;
    let match = line.match(varPattern);
    if (match) {
      const key = match[1];
      const value = match[2];

      if (value && value.length >= 8) {
        return {
          key,
          value,
          valueStart: line.indexOf(`"${value}"`) + 1, // +1 to skip opening quote
          valueEnd: line.indexOf(`"${value}"`) + 1 + value.length,
        };
      }
    }

    // 2. Object properties: key: "value"
    const objPattern = /([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*["']([^"']+)["']/;
    match = line.match(objPattern);
    if (match) {
      const key = match[1];
      const value = match[2];

      if (value && value.length >= 8) {
        return {
          key,
          value,
          valueStart: line.indexOf(`"${value}"`) + 1,
          valueEnd: line.indexOf(`"${value}"`) + 1 + value.length,
        };
      }
    }

    // 3. Simple assignments: key = "value"
    const simplePattern = /([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["']([^"']+)["']/;
    match = line.match(simplePattern);
    if (match) {
      const key = match[1];
      const value = match[2];

      if (value && value.length >= 8) {
        return {
          key,
          value,
          valueStart: line.indexOf(`"${value}"`) + 1,
          valueEnd: line.indexOf(`"${value}"`) + 1 + value.length,
        };
      }
    }

    return null;
  }

  private isSecret(key: string, value: string): boolean {
    // Skip if already a Keeper reference
    if (value.startsWith('keeper://')) {
      return false;
    }

    // Skip if too short
    if (value.length < 8) {
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
    // Handle different comment styles
    const commentPatterns = [
      /^\s*\/\//, // JavaScript/TypeScript/Java/C# single line
      /^\s*#/, // Python/Ruby/Bash single line
      /^\s*\/\*/, // JavaScript/TypeScript/Java/C# multi-line start
      /^\s*\*/, // JavaScript/TypeScript/Java/C# multi-line continuation
      /^\s*<!--/, // HTML/XML comment start
      /^\s*-->/, // HTML/XML comment end
      /^\s*$/, // Empty line
      /^\s*\/\/\/\//, // Documentation comments
      /^\s*#\s*!/, // Shebang
    ];

    return commentPatterns.some((pattern) => pattern.test(line));
  }
}
