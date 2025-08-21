import * as vscode from 'vscode';
import { Parser, ParserMatch } from '../secret-detection/parser/parser';
import { logger } from '../utils/logger';

export class SecretDetectionCodeLensProvider
  implements vscode.CodeLensProvider
{
  private _onDidChangeCodeLenses: vscode.EventEmitter<void> =
    new vscode.EventEmitter<void>();
  public readonly onDidChangeCodeLenses: vscode.Event<void> =
    this._onDidChangeCodeLenses.event;

  constructor(
    private parserFactory: (document: vscode.TextDocument) => Parser | null
  ) {}

  public refresh(): void {
    this._onDidChangeCodeLenses.fire();
  }

  public provideCodeLenses(
    document: vscode.TextDocument
  ): vscode.ProviderResult<vscode.CodeLens[]> {
    const codeLenses: vscode.CodeLens[] = [];

    try {
      // Get appropriate parser for this document
      const parser = this.parserFactory(document);
      if (!parser) {
        return codeLenses; // No parser for this file type
      }

      // Parse document and get matches
      const matches = parser.getMatches();

      // Create CodeLens for each match
      for (const match of matches) {
        const codeLens = this.createSecretCodeLens(match, document);
        if (codeLens) {
          codeLenses.push(codeLens);
        }
      }

      // Only log when there are actual CodeLens items
      if (codeLenses.length > 0) {
        logger.logDebug(
          `Created ${codeLenses.length} CodeLens items for ${document.fileName}`
        );
      }
    } catch (error) {
      logger.logError('Error providing CodeLens', error);
    }

    return codeLenses;
  }

  private createSecretCodeLens(
    match: ParserMatch,
    document: vscode.TextDocument
  ): vscode.CodeLens | null {
    try {
      const command: vscode.Command = {
        title: '$(lock) Save in Keeper Security',
        command: 'ks-vscode.saveValueToVault',
        arguments: [match.fieldValue, match.range, document.uri],
      };

      return new vscode.CodeLens(match.range, command);
    } catch (error) {
      logger.logError('Error creating CodeLens', error);
      return null;
    }
  }
}
