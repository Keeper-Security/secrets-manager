import {
  ExtensionContext,
  Disposable,
  workspace,
  languages,
  TextDocument,
} from 'vscode';
import { logger } from '../utils/logger';
import { documentMatcher, isEnvironmentFile } from '../utils/helper';
import { Parser } from '../secret-detection/parser/parser';
import JsonConfigParser from '../secret-detection/parser/jsonConfig';
import DotEnvParser from '../secret-detection/parser/dotEnv';
import YamlConfigParser from '../secret-detection/parser/yamlConfig';
import CodeParser from '../secret-detection/parser/codeParser';
import { SecretDetectionCodeLensProvider } from '../providers/secretDetectionCodeLensProvider';
import { configuration, ConfigurationKey } from './configurations';
import path from 'path';

export class SecretDetectionService {
  private subscriptions: Disposable[] = [];
  private codeLensProvider!: SecretDetectionCodeLensProvider;

  // @ts-ignore
  public constructor(private context: ExtensionContext) {
    logger.logDebug('Initializing SecretDetectionService');
    this.initialize();
    logger.logDebug('SecretDetectionService initialization completed');

    configuration.onDidChange(this.initialize.bind(this));
  }

  private initialize(): void {
    logger.logDebug('Starting secret detection initialization');
    // Clean up existing subscriptions
    for (const subscription of this.subscriptions) {
      subscription.dispose();
    }

    if (!configuration.get<boolean>(ConfigurationKey.SecretDetectionEnabled)) {
      logger.logDebug('Secret detection is disabled in the extension settings');
      return;
    }

    // Create CodeLens provider with parser-based detection
    logger.logDebug('Creating CodeLens provider');
    this.codeLensProvider = new SecretDetectionCodeLensProvider(
      this.createParserFactory()
    );

    // Register the provider
    logger.logDebug('Registering CodeLens provider and event listeners');
    this.subscriptions = [
      languages.registerCodeLensProvider(
        { scheme: 'file' },
        this.codeLensProvider
      ),
      // Add refresh listeners
      workspace.onDidSaveTextDocument(() => {
        logger.logDebug('Document saved, refreshing CodeLens');
        this.codeLensProvider.refresh();
      }),
    ];
    logger.logDebug('Secret detection initialization completed');
  }

  private createParserFactory() {
    return (document: TextDocument): Parser | null => {
      const matchDocument = documentMatcher(document);
      logger.logDebug(`Creating parser for document: ${document.fileName}`);

      // Environment files
      if (isEnvironmentFile(path.basename(document.fileName))) {
        logger.logDebug('Using DotEnv parser');
        return new DotEnvParser(document);
      }

      // JSON configuration files
      if (matchDocument(['json'], ['json'])) {
        logger.logDebug('Using JsonConfig parser');
        return new JsonConfigParser(document);
      }

      // YAML configuration files
      if (matchDocument(['yaml'], ['yml', 'yaml'])) {
        logger.logDebug('Using YamlConfig parser');
        return new YamlConfigParser(document);
      }

      // Code files
      if (
        matchDocument(
          [
            'javascript',
            'typescript',
            'python',
            'go',
            'java',
            'csharp',
            'php',
            'ruby',
          ],
          ['js', 'ts', 'jsx', 'tsx', 'py', 'go', 'java', 'cs', 'php', 'rb']
        )
      ) {
        logger.logDebug('Using Code parser');
        return new CodeParser(document);
      }

      logger.logDebug('No suitable parser found for document type');
      return null; // No parser for this file type
    };
  }

  public dispose(): void {
    logger.logDebug('Disposing SecretDetectionService');
    for (const subscription of this.subscriptions) {
      subscription.dispose();
    }
    logger.logDebug('SecretDetectionService disposal completed');
  }
}
