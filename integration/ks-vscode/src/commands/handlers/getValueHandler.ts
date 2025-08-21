import { window } from 'vscode';
import { BaseCommandHandler } from './baseCommandHandler';
import { KEEPER_NOTATION_FIELD_TYPES } from '../../utils/constants';
import { createKeeperReference } from '../../utils/helper';
import { logger } from '../../utils/logger';
import { COMMANDS } from '../../utils/constants';
import { ICliListCommandResponse, IField } from '../../types';
import { safeJsonParse } from '../../utils/helper';

export class GetValueHandler extends BaseCommandHandler {
  async execute(): Promise<void> {
    try {
      logger.logDebug('GetValueHandler.execute called');

      if (!(await this.canExecute())) {
        logger.logDebug(
          'GetValueHandler.execute: canExecute returned false, aborting'
        );
        return;
      }

      logger.logDebug('GetValueHandler: Showing spinner for secret retrieval');
      this.spinner.show('Retrieving secrets...');

      // Sync-down the latest records from the vault
      logger.logDebug('GetValueHandler: Syncing down latest records from vault');
      await this.cliService.executeCommanderCommand('sync-down');

      // List available records
      logger.logDebug(
        'GetValueHandler: Executing list command to get available records'
      );
      const records = await this.cliService.executeCommanderCommand('list', [
        '--format=json',
      ]);

      // Use safe parser that cleans output first
      const recordsList: ICliListCommandResponse[] = safeJsonParse(records, []);
      logger.logDebug(
        `GetValueHandler: Retrieved ${recordsList.length} records from vault`
      );

      this.spinner.hide();

      if (recordsList.length === 0) {
        logger.logError('GetValueHandler: No records found in vault');
        window.showInformationMessage(
          'No records found in vault. Please create a new record first.'
        );
        return;
      }

      // Show picker for available records
      const selectedRecord = await window.showQuickPick(
        recordsList.map((record) => ({
          label: record.title,
          value: record['record_uid'],
        })),
        {
          title: 'Available records from Keeper Vault',
          placeHolder: 'Select a record',
          matchOnDetail: true,
          ignoreFocusOut: true,
        }
      );

      if (!selectedRecord) {
        logger.logDebug('GetValueHandler: User cancelled record selection');
        return;
      }
      logger.logDebug(
        `GetValueHandler: User selected record - title length: ${selectedRecord.label?.length || 0}, UID length: ${selectedRecord.value?.length || 0}`
      );

      logger.logDebug(
        'GetValueHandler: Showing spinner for record details retrieval'
      );
      this.spinner.show('Retrieving secrets details...');

      // Get record details
      logger.logDebug(
        `GetValueHandler: Executing get command for record UID length: ${selectedRecord.value?.length || 0}`
      );
      const recordDetails = await this.cliService.executeCommanderCommand(
        'get',
        [selectedRecord.value, '--format=json']
      );
      // Use safe parser that cleans output first
      const details = safeJsonParse(recordDetails, [])[0];
      logger.logDebug(
        `GetValueHandler: Retrieved record details with ${details.fields?.length || 0} fields and ${details.custom?.length || 0} custom fields`
      );

      this.spinner.hide();

      if (details.length === 0) {
        logger.logError('GetValueHandler: No record details found');
        window.showInformationMessage(
          'No record details found. Please add a field to the record first.'
        );
        return;
      }

      // Show field picker
      const fields = details['fields']
        .filter((field: IField) => field.value.length > 0)
        .map((field: IField) => ({
          label: field.label ?? field.type,
          value: field.label ?? field.type,
          fieldType: KEEPER_NOTATION_FIELD_TYPES.FIELD,
        }));
      const customFields = details['custom']
        .filter((field: IField) => field.value.length > 0)
        .map((field: IField) => ({
          label: field.label ?? field.type,
          value: field.label ?? field.type,
          fieldType: KEEPER_NOTATION_FIELD_TYPES.CUSTOM_FIELD,
        }));

      const fieldsToShow = [...fields, ...customFields];

      const selectedField = await window.showQuickPick(fieldsToShow, {
        title: `Available fields from record: ${selectedRecord.label}`,
        placeHolder: 'Which field do you want to retrieve?',
        matchOnDetail: true,
        ignoreFocusOut: true,
      });

      if (!selectedField) {
        logger.logDebug('GetValueHandler: User cancelled field selection');
        return;
      }
      logger.logDebug(
        `GetValueHandler: User selected field - label length: ${selectedField.label?.length || 0}, type: ${selectedField.fieldType}`
      );

      const recordRef = createKeeperReference(
        selectedRecord.value.trim(),
        selectedField.fieldType,
        selectedField.label
      );
      if (!recordRef) {
        logger.logError(
          `${COMMANDS.GET_VALUE_FROM_VAULT}: Failed to create keeper reference for secret: ${selectedRecord.label}`
        );
        throw new Error(
          'Something went wrong while generating a password! Please try again.'
        );
      }

      // Insert the Keeper Notation reference at the cursor position
      logger.logDebug(
        `GetValueHandler: Inserting reference at cursor position - reference length: ${recordRef?.length || 0}`
      );
      const editor = window.activeTextEditor;
      if (editor) {
        await editor.edit((editBuilder) => {
          editBuilder.insert(editor.selection.active, recordRef);
        });
        logger.logDebug('GetValueHandler: Reference inserted successfully');
      }

      window.showInformationMessage(
        `Reference of "${selectedField.label}" field of secret "${selectedRecord.label}" retrieved successfully!`
      );
    } catch (error: unknown) {
      logger.logError(
        `GetValueHandler.execute failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        error
      );
      window.showErrorMessage(
        `Failed to get value: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    } finally {
      this.spinner.hide();
    }
  }
}
