/* eslint-disable @typescript-eslint/explicit-function-return-type */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { CliService } from '../../../../src/services/cli';
import { StatusBarSpinner } from '../../../../src/utils/helper';
import { SaveValueHandler } from '../../../../src/commands/handlers/saveValueHandler';
import { StorageManager } from '../../../../src/commands/storage/storageManager';
import { ExtensionContext, window, workspace, Range, Uri, Selection } from 'vscode';
import { logger } from '../../../../src/utils/logger';
import { KEEPER_NOTATION_FIELD_TYPES } from '../../../../src/utils/constants';

// Mock dependencies
jest.mock('../../../../src/utils/helper', () => ({
  StatusBarSpinner: jest.fn(),
  createKeeperReference: jest.fn(),
  resolveFolderPaths: jest.fn()
}));
jest.mock('../../../../src/services/cli');
jest.mock('../../../../src/commands/storage/storageManager');
jest.mock('../../../../src/utils/logger');
jest.mock('../../../../src/commands/utils/commandUtils', () => ({
  CommandUtils: {
    getSecretNameFromUser: jest.fn(),
    getSecretFieldNameFromUser: jest.fn(),
    getFieldType: jest.fn()
  }
}));
jest.mock('vscode', () => ({
  ...jest.requireActual('vscode'),
  window: {
    showInputBox: jest.fn(),
    showQuickPick: jest.fn(),
    showInformationMessage: jest.fn(),
    showErrorMessage: jest.fn(),
    activeTextEditor: null,
    showTextDocument: jest.fn(),
    createOutputChannel: jest.fn(() => ({
      appendLine: jest.fn(),
      append: jest.fn(),
      show: jest.fn(),
      hide: jest.fn(),
      dispose: jest.fn(),
      clear: jest.fn()
    }))
  },
  workspace: {
    openTextDocument: jest.fn()
  },
  Range: jest.fn().mockImplementation((startLine, startChar, endLine, endChar) => ({
    start: { line: startLine, character: startChar },
    end: { line: endLine, character: endChar }
  })),
  Uri: {
    parse: jest.fn().mockImplementation((uriString) => ({
      toString: () => uriString
    }))
  },
  Selection: jest.fn().mockImplementation((start, end) => ({
    start,
    end
  }))
}));

describe('SaveValueHandler', () => {
  let mockCliService: jest.Mocked<CliService>;
  let mockContext: ExtensionContext;
  let mockSpinner: jest.Mocked<StatusBarSpinner>;
  let mockStorageManager: jest.Mocked<StorageManager>;
  let saveValueHandler: SaveValueHandler;
  let mockCreateKeeperReference: jest.Mock;
  let mockCommandUtils: any;
  let mockLogger: jest.Mocked<typeof logger>;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockCliService = {
      isCLIReady: jest.fn(),
      executeCommanderCommand: jest.fn()
    } as unknown as jest.Mocked<CliService>;

    mockContext = {} as ExtensionContext;
    
    mockSpinner = {
      show: jest.fn(),
      updateMessage: jest.fn(),
      hide: jest.fn(),
      dispose: jest.fn()
    } as unknown as jest.Mocked<StatusBarSpinner>;
    
    mockStorageManager = {
      ensureValidStorage: jest.fn(),
      getCurrentStorage: jest.fn()
    } as unknown as jest.Mocked<StorageManager>;

    mockCreateKeeperReference = require('../../../../src/utils/helper').createKeeperReference;
    mockCommandUtils = require('../../../../src/commands/utils/commandUtils').CommandUtils;
    mockLogger = require('../../../../src/utils/logger').logger;

    saveValueHandler = new SaveValueHandler(mockCliService, mockContext, mockSpinner, mockStorageManager);
  });

  describe('constructor', () => {
    it('should initialize with dependencies', () => {
      expect(saveValueHandler).toBeInstanceOf(SaveValueHandler);
    });
  });

  describe('execute - CodeLens Integration', () => {
    it('should handle CodeLens-provided values (secretValue, range, documentUri)', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockDocument = { uri: { toString: () => 'file://test.txt' } };
      const mockEditor = {
        document: { uri: { toString: () => 'file://different.txt' } },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;
      (workspace.openTextDocument as jest.Mock).mockResolvedValue(mockDocument);
      (window.showTextDocument as jest.Mock).mockResolvedValue(mockEditor);

      const range = new Range(1, 0, 1, 10);
      const uri = Uri.parse('file://test.txt');
      
      await saveValueHandler.execute('secret-value', range, uri);

      expect(workspace.openTextDocument).toHaveBeenCalledWith(uri);
      expect(window.showTextDocument).toHaveBeenCalledWith(mockDocument);
      expect(mockEditor.edit).toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should not open document if already active', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { uri: { toString: () => 'file://test.txt' } },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      const range = new Range(1, 0, 1, 10);
      const uri = Uri.parse('file://test.txt');
      
      await saveValueHandler.execute('secret-value', range, uri);

      expect(workspace.openTextDocument).not.toHaveBeenCalled();
      expect(window.showTextDocument).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should set editor selection to detected range', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { uri: { toString: () => 'file://test.txt' } },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      const range = new Range(1, 0, 1, 10);
      const uri = Uri.parse('file://test.txt');
      
      await saveValueHandler.execute('secret-value', range, uri);

      expect(mockEditor.selection).toEqual(new Selection(range.start, range.end));
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('execute - Manual Selection Mode', () => {
    it('should execute successfully when CLI is ready with manual selection', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCliService.isCLIReady).toHaveBeenCalled();
      expect(mockStorageManager.ensureValidStorage).toHaveBeenCalled();
      expect(mockCommandUtils.getSecretNameFromUser).toHaveBeenCalled();
      expect(mockCommandUtils.getSecretFieldNameFromUser).toHaveBeenCalled();
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('record-add', [
        '--title="Test Record"',
        '--record-type=login',
        '"c.secret.password"="selected-text"',
        '--folder="123"'
      ]);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle no text selection in manual mode', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(window.showErrorMessage).toHaveBeenCalledWith('Please make a selection to save its value.');
      expect(mockCliService.isCLIReady).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle whitespace-only text selection', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('   ') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 3 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(window.showErrorMessage).toHaveBeenCalledWith('No value found to save.');
      expect(mockCliService.isCLIReady).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle text with leading/trailing whitespace', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('  secret-value  ') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 17 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('record-add', [
        '--title="Test Record"',
        '--record-type=login',
        '"c.secret.password"="secret-value"',
        '--folder="123"'
      ]);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('execute - CLI Readiness', () => {
    it('should not execute when CLI is not ready', async () => {
      mockCliService.isCLIReady.mockResolvedValue(false);
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCliService.isCLIReady).toHaveBeenCalled();
      expect(mockStorageManager.ensureValidStorage).not.toHaveBeenCalled();
      expect(mockCommandUtils.getSecretNameFromUser).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('execute - User Input Handling', () => {
    it('should handle user cancellation of secret name input', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      mockCommandUtils.getSecretNameFromUser.mockRejectedValue(new Error('No record name provided.'));
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCommandUtils.getSecretNameFromUser).toHaveBeenCalled();
      expect(mockCommandUtils.getSecretFieldNameFromUser).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle user cancellation of field name input', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockRejectedValue(new Error('No record field name provided.'));
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCommandUtils.getSecretNameFromUser).toHaveBeenCalled();
      expect(mockCommandUtils.getSecretFieldNameFromUser).toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('execute - Storage Scenarios', () => {
    it('should handle "My Vault" folder (no folder arg)', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '/', name: 'My Vault', parentUid: '/', folderPath: '/' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('record-add', [
        '--title="Test Record"',
        '--record-type=login',
        '"c.secret.password"="selected-text"'
        // No --folder argument for "My Vault"
      ]);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle custom folder with folder arg', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: 'custom-folder', name: 'Custom Folder', parentUid: '/', folderPath: '/Custom Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('record-add', [
        '--title="Test Record"',
        '--record-type=login',
        '"c.secret.password"="selected-text"',
        '--folder="custom-folder"'
      ]);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('execute - Error Scenarios', () => {
    it('should handle storage validation failure', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockRejectedValue(new Error('Storage validation failed'));
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockStorageManager.ensureValidStorage).toHaveBeenCalled();
      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to save secret: Storage validation failed');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle CLI command failure', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockRejectedValue(new Error('CLI command failed'));
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalled();
      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to save secret: CLI command failed');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle Keeper reference creation failure', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue(null);
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCreateKeeperReference).toHaveBeenCalledWith('record123', KEEPER_NOTATION_FIELD_TYPES.CUSTOM_FIELD, 'password');
      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to save secret: Something went wrong while generating a password! Please try again.');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle editor edit failure', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockRejectedValue(new Error('Editor edit failed'))
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockEditor.edit).toHaveBeenCalled();
      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to save secret: Editor edit failed');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle non-Error objects in catch block', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockRejectedValue('String error');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to save secret: Unknown error');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('execute - Success Scenarios', () => {
    it('should show success message when secret is saved', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(window.showInformationMessage).toHaveBeenCalledWith('Secret saved to keeper vault at "Test Folder" folder successfully!');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should replace selected text with Keeper reference in manual mode', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockEditor.edit).toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should replace detected range with Keeper reference in CodeLens mode', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { uri: { toString: () => 'file://test.txt' } },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      const range = new Range(1, 0, 1, 10);
      const uri = Uri.parse('file://test.txt');
      
      await saveValueHandler.execute('secret-value', range, uri);

      expect(mockEditor.edit).toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('execute - Field Type Handling', () => {
    it('should handle different field types correctly', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('api-key');
      mockCommandUtils.getFieldType.mockReturnValue('text');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/api-key');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('record-add', [
        '--title="Test Record"',
        '--record-type=login',
        '"c.text.api-key"="selected-text"',
        '--folder="123"'
      ]);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('execute - Spinner Management', () => {
    it('should show spinner during secret saving', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockSpinner.show).toHaveBeenCalledWith('Saving secret to keeper vault...');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should hide spinner even when errors occur', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockRejectedValue(new Error('Storage error'));
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('execute - Logging Coverage', () => {
    it('should log errors properly', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockRejectedValue(new Error('Storage error'));
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue('selected-text') },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockLogger.logError).toHaveBeenCalledWith('SaveValueHandler.execute failed: Storage error', expect.any(Error));
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('execute - Edge Cases', () => {
    it('should handle very long text selection', async () => {
      const longText = 'a'.repeat(10000);
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue(longText) },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: 10000 } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('record-add', [
        '--title="Test Record"',
        '--record-type=login',
        `"c.secret.password"="${longText}"`,
        '--folder="123"'
      ]);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle text with special characters', async () => {
      const specialText = 'password@#$%^&*()_+-=[]{}|;:,.<>?';
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.ensureValidStorage.mockResolvedValue();
      mockStorageManager.getCurrentStorage.mockReturnValue({ folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' });
      
      mockCommandUtils.getSecretNameFromUser.mockResolvedValue('Test Record');
      mockCommandUtils.getSecretFieldNameFromUser.mockResolvedValue('password');
      mockCommandUtils.getFieldType.mockReturnValue('secret');
      mockCliService.executeCommanderCommand.mockResolvedValue('record123');
      mockCreateKeeperReference.mockReturnValue('keeper://record123/custom_field/password');
      
      const mockEditor = {
        document: { getText: jest.fn().mockReturnValue(specialText) },
        selection: { start: { line: 0, character: 0 }, end: { line: 0, character: specialText.length } },
        edit: jest.fn().mockResolvedValue(true)
      };
      (window as any).activeTextEditor = mockEditor;

      await saveValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('record-add', [
        '--title="Test Record"',
        '--record-type=login',
        `"c.secret.password"="${specialText}"`,
        '--folder="123"'
      ]);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle null/undefined editor gracefully', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      (window as any).activeTextEditor = null;

      await saveValueHandler.execute();

      expect(window.showErrorMessage).toHaveBeenCalledWith('Please make a selection to save its value.');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });
});
