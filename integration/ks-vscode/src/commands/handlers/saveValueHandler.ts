import { window, ExtensionContext } from 'vscode';
import { CliService } from '../../services/cli';
import { StatusBarSpinner } from '../../utils/helper';
import {
  KEEPER_NOTATION_FIELD_TYPES,
  KEEPER_RECORD_TYPES,
} from '../../utils/constants';
import { createKeeperReference } from '../../utils/helper';
import { logger } from '../../utils/logger';
import { COMMANDS } from '../../utils/constants';
import { workspace, Range, Uri, Selection } from 'vscode';
import { BaseCommandHandler } from './baseCommandHandler';
import { StorageManager } from '../storage/storageManager';
import { CommandUtils } from '../utils/commandUtils';

export class SaveValueHandler extends BaseCommandHandler {
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

  async execute(
    secretValue?: string,
    range?: Range,
    documentUri?: Uri
  ): Promise<void> {
    try {
      logger.logDebug(
        `SaveValueHandler.execute called - hasSecretValue: ${!!secretValue}, hasRange: ${!!range}, hasUri: ${!!documentUri}`
      );

      let selectedText: string | undefined;
      let editor = window.activeTextEditor;

      // If called from CodeLens, use provided values
      if (secretValue && range && documentUri) {
        logger.logDebug(
          `SaveValueHandler: Using CodeLens values - secretValueLength: ${secretValue.length}, range: ${range.start.line}:${range.start.character}-${range.end.line}:${range.end.character}`
        );
        selectedText = secretValue;
        // Open the document if not already active
        if (editor?.document.uri.toString() !== documentUri.toString()) {
          const document = await workspace.openTextDocument(documentUri);
          editor = await window.showTextDocument(document);
        }

        // Set the selection to the detected range
        if (editor) {
          editor.selection = new Selection(range.start, range.end);
        }
      } else {
        logger.logDebug('SaveValueHandler: Using manual selection mode');
        // Manual selection mode
        selectedText = editor?.document.getText(editor?.selection);
        if (!selectedText) {
          logger.logDebug('SaveValueHandler: No text selected by user');
          window.showErrorMessage('Please make a selection to save its value.');
          return;
        }
        logger.logDebug(
          `SaveValueHandler: Selected text length: ${selectedText.length}`
        );
      }

      // Trim the selected text
      selectedText = selectedText?.trim();

      // Validate that we have text to save
      if (!selectedText) {
        window.showErrorMessage('No value found to save.');
        return;
      }

      if (!(await this.canExecute())) {
        logger.logDebug(
          'SaveValueHandler.execute: canExecute returned false, aborting'
        );
        return;
      }

      // Get secret name from user
      logger.logDebug('SaveValueHandler: Getting secret name from user');
      const recordName = await CommandUtils.getSecretNameFromUser(
        COMMANDS.SAVE_VALUE_TO_VAULT
      );
      logger.logDebug(
        `SaveValueHandler: User provided record name length: ${recordName?.length || 0}`
      );

      logger.logDebug('SaveValueHandler: Getting secret field name from user');
      const recordFieldName = await CommandUtils.getSecretFieldNameFromUser(
        COMMANDS.SAVE_VALUE_TO_VAULT
      );
      logger.logDebug(
        `SaveValueHandler: User provided field name length: ${recordFieldName?.length || 0}`
      );

      logger.logDebug('SaveValueHandler: Ensuring valid storage');
      await this.storageManager.ensureValidStorage();

      this.spinner.show('Saving secret to keeper vault...');

      const currentStorage = this.storageManager.getCurrentStorage();

      /**
       *
       * [<FIELD_SET>][<FIELD_TYPE>][<FIELD_LABEL>]=[FIELD_VALUE]
       *
       * `"c.${CommandUtils.getFieldType(recordFieldName)}.${recordFieldName}"="${selectedText}"`
       *
       * Create custom field with detect recordFieldName that can be secret or text
       */

      const args = [
        `--title="${recordName}"`,
        `--record-type=${KEEPER_RECORD_TYPES.LOGIN}`,
        `"c.${CommandUtils.getFieldType(recordFieldName)}.${recordFieldName}"="${selectedText}"`,
      ];

      // if currentStorage is not "My Vault", then add folder to args
      if (currentStorage?.folderUid !== '/') {
        args.push(`--folder="${currentStorage?.folderUid}"`);
      }

      logger.logDebug(
        `SaveValueHandler: Executing record-add command with ${args.length} arguments`
      );
      const recordUid = await this.cliService.executeCommanderCommand(
        'record-add',
        args
      );
      logger.logDebug(
        `SaveValueHandler: Record created successfully with UID length: ${recordUid?.length || 0}`
      );

      // Create a Keeper Notation reference for the secret
      const recordRef = createKeeperReference(
        recordUid.trim(),
        KEEPER_NOTATION_FIELD_TYPES.CUSTOM_FIELD,
        recordFieldName
      );
      if (!recordRef) {
        logger.logError(
          `${COMMANDS.SAVE_VALUE_TO_VAULT}: Failed to create keeper reference for secret: ${recordName}`
        );
        throw new Error(
          'Something went wrong while generating a password! Please try again.'
        );
      }

      // Insert the Keeper Notation reference
      if (editor) {
        await editor.edit((editBuilder) => {
          if (range) {
            // Replace the detected secret range
            editBuilder.replace(range, recordRef);
          } else {
            // Replace the current selection
            editBuilder.replace(editor.selection, recordRef);
          }
        });
      }

      window.showInformationMessage(
        `Secret saved to keeper vault at "${currentStorage?.name}" folder successfully!`
      );
    } catch (error: unknown) {
      logger.logError(
        `SaveValueHandler.execute failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        error
      );
      window.showErrorMessage(
        `Failed to save secret: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    } finally {
      this.spinner.hide();
    }
  }
}
