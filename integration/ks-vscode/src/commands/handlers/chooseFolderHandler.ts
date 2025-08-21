import { ExtensionContext, window } from 'vscode';
import { CliService } from '../../services/cli';
import { StatusBarSpinner } from '../../utils/helper';
import { BaseCommandHandler } from './baseCommandHandler';
import { StorageManager } from '../storage/storageManager';
import { logger } from '../../utils/logger';

export class ChooseFolderHandler extends BaseCommandHandler {
  private storageManager: StorageManager;

  constructor(
    cliService: CliService,
    context: ExtensionContext,
    spinner: StatusBarSpinner,
    storageManager: StorageManager
  ) {
    super(cliService, context, spinner);
    this.storageManager = storageManager;
  }

  async execute(): Promise<void> {
    try {
      logger.logDebug('ChooseFolderHandler.execute called');

      if (!(await this.canExecute())) {
        logger.logDebug(
          'ChooseFolderHandler.execute: canExecute returned false, aborting'
        );
        return;
      }

      logger.logDebug('ChooseFolderHandler: Starting folder selection process');
      await this.storageManager.chooseFolder();
      logger.logDebug('ChooseFolderHandler: Folder selection completed');
    } catch (error) {
      logger.logError(
        `ChooseFolderHandler.execute failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        error
      );
      window.showErrorMessage(
        `Failed to choose folder: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    } finally {
      this.spinner.hide();
    }
  }
}
