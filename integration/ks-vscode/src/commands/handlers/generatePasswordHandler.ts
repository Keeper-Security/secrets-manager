import { window, ExtensionContext } from 'vscode';
import { CliService } from '../../services/cli';
import { StatusBarSpinner } from '../../utils/helper';
import {
  KEEPER_FIELD_TYPES,
  KEEPER_NOTATION_FIELD_TYPES,
  KEEPER_RECORD_TYPES,
} from '../../utils/constants';
import { createKeeperReference } from '../../utils/helper';
import { logger } from '../../utils/logger';
import { COMMANDS } from '../../utils/constants';
import { CommandUtils } from '../utils/commandUtils';
import { StorageManager } from '../storage/storageManager';
import { BaseCommandHandler } from './baseCommandHandler';

export class GeneratePasswordHandler extends BaseCommandHandler {
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
      logger.logDebug('GeneratePasswordHandler.execute called');

      if (!(await this.canExecute())) {
        logger.logDebug(
          'GeneratePasswordHandler.execute: canExecute returned false, aborting'
        );
        return;
      }

      // Get secret name from user
      logger.logDebug('GeneratePasswordHandler: Getting secret name from user');
      const recordName = await CommandUtils.getSecretNameFromUser(
        COMMANDS.GENERATE_PASSWORD
      );
      logger.logDebug(
        `GeneratePasswordHandler: User provided record name length: ${recordName?.length || 0}`
      );

      logger.logDebug(
        'GeneratePasswordHandler: Getting secret field name from user'
      );
      const recordFieldName = await CommandUtils.getSecretFieldNameFromUser(
        COMMANDS.GENERATE_PASSWORD
      );
      logger.logDebug(
        `GeneratePasswordHandler: User provided field name length: ${recordFieldName?.length || 0}`
      );

      logger.logDebug('GeneratePasswordHandler: Ensuring valid storage');
      await this.storageManager.ensureValidStorage();

      logger.logDebug(
        'GeneratePasswordHandler: Showing spinner for password generation'
      );
      this.spinner.show('Generating password...');

      // Generate a random password
      logger.logDebug('GeneratePasswordHandler: Executing generate command');
      const password = await this.cliService.executeCommanderCommand(
        'generate',
        ['-q', '-nb']
      );
      if (!password) {
        logger.logError(
          `${COMMANDS.GENERATE_PASSWORD}: Failed to generate a password.`
        );
        throw new Error(
          'Something went wrong while generating a password! Please try again.'
        );
      }
      logger.logDebug(
        `GeneratePasswordHandler: Password generated successfully, length: ${password.length}`
      );

      const currentStorage = this.storageManager.getCurrentStorage();

      const args = [
        `--title="${recordName}"`,
        `--record-type=${KEEPER_RECORD_TYPES.LOGIN}`,
        `"c.${KEEPER_FIELD_TYPES.SECRET}.${recordFieldName}"="${password}"`,
      ];

      // if currentStorage is not "My Vault", then add folder to args
      if (currentStorage?.folderUid !== '/') {
        args.push(`--folder="${currentStorage?.folderUid}"`);
      }

      logger.logDebug(
        `GeneratePasswordHandler: Executing record-add command with ${args.length} arguments`
      );
      const recordUid = await this.cliService.executeCommanderCommand(
        'record-add',
        args
      );
      logger.logDebug(
        `GeneratePasswordHandler: Record created successfully with UID length: ${recordUid?.length || 0}`
      );

      // Create a Keeper Notation reference for the password
      const recordRef = createKeeperReference(
        recordUid.trim(),
        KEEPER_NOTATION_FIELD_TYPES.CUSTOM_FIELD,
        recordFieldName
      );
      if (!recordRef) {
        logger.logError(
          `${COMMANDS.GENERATE_PASSWORD}: Failed to create keeper reference for secret: ${recordName}`
        );
        throw new Error(
          'Something went wrong while generating a password! Please try again.'
        );
      }

      // Insert the Keeper Notation reference at the cursor position
      logger.logDebug(
        `GeneratePasswordHandler: Inserting reference at cursor position - reference length: ${recordRef?.length || 0}`
      );
      const editor = window.activeTextEditor;
      if (editor) {
        await editor.edit((editBuilder) => {
          editBuilder.insert(editor.selection.active, recordRef);
        });
        logger.logDebug(
          'GeneratePasswordHandler: Reference inserted successfully'
        );
      }

      window.showInformationMessage(
        `Password generated and saved to keeper vault at "${currentStorage?.name}" folder successfully!`
      );
    } catch (error: unknown) {
      logger.logError(
        `GeneratePasswordHandler.execute failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        error
      );
      window.showErrorMessage(
        `Failed to generate password: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    } finally {
      this.spinner.hide();
    }
  }
}
