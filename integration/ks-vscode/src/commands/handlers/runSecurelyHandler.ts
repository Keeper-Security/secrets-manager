import { window, workspace } from 'vscode';
import { KEEPER_NOTATION_FIELD_TYPES } from '../../utils/constants';
import {
  isEnvironmentFile,
  parseKeeperReference,
  validateKeeperReference,
  safeJsonParse,
} from '../../utils/helper';
import { logger } from '../../utils/logger';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { FieldExtractor } from '../utils/fieldExtractor';
import { BaseCommandHandler } from './baseCommandHandler';

export class RunSecurelyHandler extends BaseCommandHandler {
  async execute(): Promise<void> {
    logger.logDebug('RunSecurelyHandler.execute called');

    if (!(await this.canExecute())) {
      logger.logDebug(
        'RunSecurelyHandler.execute: canExecute returned false, aborting'
      );
      return;
    }

    try {
      logger.logDebug('RunSecurelyHandler: Starting workspace selection');
      const workspaceRoot = await this.selectWorkspace();
      logger.logDebug(
        `RunSecurelyHandler: Selected workspace path length: ${workspaceRoot?.length || 0}`
      );

      logger.logDebug(
        'RunSecurelyHandler: Starting environment file selection'
      );
      const selectedEnvFile = await this.selectEnvironmentFile(workspaceRoot);
      logger.logDebug(
        `RunSecurelyHandler: Selected environment file path length: ${selectedEnvFile?.length || 0}`
      );

      logger.logDebug('RunSecurelyHandler: Getting command from user');
      const command = await this.getCommandFromUser();
      logger.logDebug(
        `RunSecurelyHandler: User provided command length: ${command?.length || 0}`
      );

      logger.logDebug('RunSecurelyHandler: Starting secret resolution');
      this.spinner.show('Resolving secrets...');

      // Sync-down the latest records from the vault
      logger.logDebug(
        'RunSecurelyHandler: Syncing down latest records from vault'
      );
      await this.cliService.executeCommanderCommand('sync-down');

      const resolvedEnv = await this.resolveSecrets(selectedEnvFile);
      logger.logDebug(
        `RunSecurelyHandler: Resolved ${Object.keys(resolvedEnv).length} secrets`
      );

      logger.logDebug('RunSecurelyHandler: Creating terminal with secrets');
      this.spinner.show('Creating terminal with secrets injected...');
      await this.createAndRunTerminal(selectedEnvFile, command, resolvedEnv);
      logger.logDebug(
        'RunSecurelyHandler: Terminal created and command started successfully'
      );

      window.showInformationMessage(`Command started with secrets injected`);
    } catch (error: unknown) {
      logger.logError(
        `RunSecurelyHandler.execute failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        error
      );
      window.showErrorMessage(
        `Failed to run securely: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    } finally {
      this.spinner.hide();
    }
  }

  /**
   * Select workspace to run securely in
   */
  private async selectWorkspace(): Promise<string> {
    logger.logDebug(
      'RunSecurelyHandler.selectWorkspace: Starting workspace selection'
    );
    const workspaceFolders = workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
      logger.logDebug(
        'RunSecurelyHandler.selectWorkspace: No workspace folders found'
      );
      throw new Error('Open a folder/workspace first');
    }

    if (workspaceFolders.length === 1) {
      logger.logDebug(
        `RunSecurelyHandler.selectWorkspace: Single workspace found - name length: ${workspaceFolders[0].name?.length || 0}`
      );
      return workspaceFolders[0].uri.fsPath;
    }

    logger.logDebug(
      `RunSecurelyHandler.selectWorkspace: Multiple workspaces found - count: ${workspaceFolders.length}`
    );
    const workspaceNames = workspaceFolders.map((folder) => folder.name);
    const selected = await window.showQuickPick(workspaceNames, {
      placeHolder: 'Select workspace to run securely in',
      matchOnDetail: true,
      ignoreFocusOut: true,
    });

    if (!selected) {
      logger.logDebug(
        'RunSecurelyHandler.selectWorkspace: User cancelled workspace selection'
      );
      throw new Error('No workspace selected');
    }

    const selectedWorkspace = workspaceFolders.find(
      (folder) => folder.name === selected
    );
    if (!selectedWorkspace) {
      logger.logDebug(
        'RunSecurelyHandler.selectWorkspace: User selected workspace not found'
      );
      throw new Error('Workspace not found');
    }
    logger.logDebug(
      `RunSecurelyHandler.selectWorkspace: User selected workspace - name length: ${selectedWorkspace.name?.length || 0}`
    );
    return selectedWorkspace.uri.fsPath;
  }

  /**
   * Select environment file to use
   */
  private async selectEnvironmentFile(workspaceRoot: string): Promise<string> {
    const envFiles = this.findEnvironmentFiles(workspaceRoot);

    if (envFiles.length === 0) {
      throw new Error('No environment files found in workspace');
    }

    if (envFiles.length === 1) {
      return envFiles[0]; // Auto-select single file
    }

    // Multiple files - let user choose
    const envFileNames = envFiles.map((file) =>
      path.relative(workspaceRoot, file)
    );
    const selected = await window.showQuickPick(envFileNames, {
      placeHolder: 'Select environment file to use',
      matchOnDetail: true,
      ignoreFocusOut: true,
    });

    if (!selected) {
      throw new Error('No environment file selected');
    }

    const selectedIndex = envFileNames.indexOf(selected);
    return envFiles[selectedIndex];
  }

  /**
   * Get command to run from user
   */
  private async getCommandFromUser(): Promise<string> {
    const command = await window.showInputBox({
      prompt: 'Enter command to run with Keeper secrets injected',
      placeHolder: 'e.g. node index.js',
      ignoreFocusOut: true,
    });

    if (!command) {
      throw new Error(
        'No command entered. Please enter a command to run with Keeper secrets injected.'
      );
    }

    return command;
  }

  /**
   * Resolve secrets from environment file
   */
  private async resolveSecrets(
    selectedEnvFile: string
  ): Promise<Record<string, string>> {
    const envFileContent = fs.readFileSync(selectedEnvFile, 'utf8');
    const envConfig = dotenv.parse(envFileContent);

    const recordGroups = this.groupKeeperReferences(envConfig);
    const resolvedEnv: Record<string, string> = {};

    if (recordGroups.size > 0) {
      await this.fetchAndResolveSecrets(recordGroups, resolvedEnv);
    }

    // Add non-keeper references
    for (const [key, value] of Object.entries(envConfig)) {
      if (!validateKeeperReference(value)) {
        resolvedEnv[key] = value;
      }
    }

    logger.logInfo(
      `Resolved ${Object.keys(resolvedEnv).length} environment variables`
    );
    return resolvedEnv;
  }

  /**
   * Group Keeper references by recordUid for batch processing
   */
  private groupKeeperReferences(envConfig: Record<string, string>): Map<
    string,
    Array<{
      key: string;
      fieldType: KEEPER_NOTATION_FIELD_TYPES;
      itemName: string;
    }>
  > {
    const recordGroups = new Map<
      string,
      Array<{
        key: string;
        fieldType: KEEPER_NOTATION_FIELD_TYPES;
        itemName: string;
      }>
    >();

    for (const [key, value] of Object.entries(envConfig)) {
      if (typeof value === 'string' && validateKeeperReference(value)) {
        const parsedRef = parseKeeperReference(value);
        if (!parsedRef) {
          logger.logError(`Failed to parse keeper:// reference: ${value}`);
          continue;
        }

        const { recordUid, fieldType, itemName } = parsedRef;

        if (!recordGroups.has(recordUid)) {
          recordGroups.set(recordUid, []);
        }
        recordGroups.get(recordUid)?.push({ key, fieldType, itemName });
      }
    }

    return recordGroups;
  }

  /**
   * Fetch and resolve secrets from Keeper vault
   */
  private async fetchAndResolveSecrets(
    recordGroups: Map<
      string,
      Array<{
        key: string;
        fieldType: KEEPER_NOTATION_FIELD_TYPES;
        itemName: string;
      }>
    >,
    resolvedEnv: Record<string, string>
  ): Promise<void> {
    // Execute commands sequentially - much simpler than queue!
    for (const [recordUid, references] of recordGroups.entries()) {
      logger.logInfo(`Fetching record: ${recordUid} with ${references.length} references`);

      try {
        const record = await this.cliService.executeCommanderCommand('get', [
          recordUid,
          '--format=json',
        ]);
        
        // Use safe parser that cleans output first
        const parsedRecords = safeJsonParse(record, []);
        
        if (!parsedRecords || parsedRecords.length === 0) {
          throw new Error('Failed to parse record data');
        }
        
        const recordDetails = parsedRecords[0];

        references.forEach(({ key, fieldType, itemName }) => {
          const value = FieldExtractor.extractFieldValue(
            recordDetails,
            fieldType,
            itemName
          );
          if (value !== null) {
            resolvedEnv[key] = value;
            logger.logInfo(`Resolved ${key}`);
          } else {
            logger.logError(
              `Failed to resolve keeper reference: keeper://${recordUid}/${fieldType}/${itemName}`
            );
            resolvedEnv[key] =
              `keeper://${recordUid}/${fieldType}/${itemName}`;
          }
        });
      } catch (error: unknown) {
        logger.logError(`Failed to fetch record ${recordUid}:`, error);
        references.forEach(({ key }) => {
          resolvedEnv[key] = `keeper://${recordUid}/error/failed_to_fetch`;
        });
      }
    }
  }

  /**
   * Create terminal and run command with injected secrets
   */
  private async createAndRunTerminal(
    selectedEnvFile: string,
    command: string,
    resolvedEnv: Record<string, string>
  ): Promise<void> {
    const terminal = window.createTerminal({
      name: 'Keeper Secure Run',
      cwd: path.dirname(selectedEnvFile),
      env: {
        ...process.env,
        ...resolvedEnv,
      },
    });

    terminal.show();
    terminal.sendText(command, true);
  }

  /**
   * Find all environment files in the workspace (only immediate subdirectories)
   */
  private findEnvironmentFiles(workspaceRoot: string): string[] {
    try {
      const foundFiles: string[] = [];

      const items = fs.readdirSync(workspaceRoot);

      for (const item of items) {
        const fullPath = path.join(workspaceRoot, item);
        const stat = fs.statSync(fullPath);

        if (stat.isFile()) {
          // Check if this file matches environment file patterns
          if (isEnvironmentFile(item)) {
            foundFiles.push(fullPath);
          }
        }
      }

      logger.logInfo(`Found environment files at: ${foundFiles.join(', ')}`);

      return foundFiles;
    } catch (error: unknown) {
      logger.logError(`Failed to find environment files: ${error}`);
      return [];
    }
  }
}
