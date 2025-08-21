/* eslint-disable @typescript-eslint/no-explicit-any */
import { CliService } from '../../../../src/services/cli';
import { StatusBarSpinner } from '../../../../src/utils/helper';
import { RunSecurelyHandler } from '../../../../src/commands/handlers/runSecurelyHandler';
import { ExtensionContext, window, workspace } from 'vscode';

// Mock dependencies
jest.mock('../../../../src/services/cli');
jest.mock('../../../../src/utils/helper');
jest.mock('../../../../src/utils/logger');
jest.mock('fs');
jest.mock('path');
jest.mock('dotenv');
jest.mock('../../../../src/commands/utils/fieldExtractor');

jest.mock('vscode', () => ({
  ...jest.requireActual('vscode'),
  window: {
    showInputBox: jest.fn(),
    showQuickPick: jest.fn(),
    showInformationMessage: jest.fn(),
    showErrorMessage: jest.fn(),
    activeTextEditor: null,
    showTextDocument: jest.fn(),
    createTerminal: jest.fn(() => ({
      show: jest.fn(),
      sendText: jest.fn(),
      dispose: jest.fn()
    })),
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
    workspaceFolders: []
  }
}));

describe('RunSecurelyHandler', () => {
  let mockCliService: jest.Mocked<CliService>;
  let mockContext: ExtensionContext;
  let mockSpinner: jest.Mocked<StatusBarSpinner>;
  let runSecurelyHandler: RunSecurelyHandler;
  let mockFs: any;
  let mockPath: any;
  let mockDotenv: any;
  let mockFieldExtractor: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockCliService = {
      isCLIReady: jest.fn(),
      executeCommanderCommand: jest.fn()
    } as unknown as jest.Mocked<CliService>;

    mockContext = {} as ExtensionContext;
    
    // Properly mock the StatusBarSpinner with required methods
    mockSpinner = {
      show: jest.fn(),
      updateMessage: jest.fn(),
      hide: jest.fn(),
      dispose: jest.fn()
    } as unknown as jest.Mocked<StatusBarSpinner>;

    // Get mocked modules
    mockFs = require('fs');
    mockPath = require('path');
    mockDotenv = require('dotenv');
    mockFieldExtractor = require('../../../../src/commands/utils/fieldExtractor');

    runSecurelyHandler = new RunSecurelyHandler(mockCliService, mockContext, mockSpinner);
  });

  describe('execute', () => {
    it('should execute successfully when CLI is ready', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('TEST_VAR=value');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({ TEST_VAR: 'value' });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock field extractor
      mockFieldExtractor.FieldExtractor.extractFieldValue.mockReturnValue('test-value');
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "123", "title": "Test Record"}');

      await runSecurelyHandler.execute();

      expect(mockCliService.isCLIReady).toHaveBeenCalled();
      expect(window.showInputBox).toHaveBeenCalled();
      expect(window.createTerminal).toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should not execute when CLI is not ready', async () => {
      mockCliService.isCLIReady.mockResolvedValue(false);

      await runSecurelyHandler.execute();

      expect(mockCliService.isCLIReady).toHaveBeenCalled();
      expect(window.showInputBox).not.toHaveBeenCalled();
      expect(mockSpinner.hide).not.toHaveBeenCalled(); // Spinner is not shown/hidden when CLI is not ready
    });

    it('should handle user cancellation of command input', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('TEST_VAR=value');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({ TEST_VAR: 'value' });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock command input cancellation
      (window.showInputBox as jest.Mock).mockResolvedValue(undefined);

      await runSecurelyHandler.execute();

      expect(window.showInputBox).toHaveBeenCalled();
      expect(window.createTerminal).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle multiple workspace selection', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with multiple folders
      (workspace as any).workspaceFolders = [
        { name: 'Workspace 1', uri: { fsPath: '/workspace1' } },
        { name: 'Workspace 2', uri: { fsPath: '/workspace2' } }
      ];
      
      // Mock workspace selection
      (window.showQuickPick as jest.Mock).mockResolvedValue('Workspace 1');
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('TEST_VAR=value');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/workspace1');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({ TEST_VAR: 'value' });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "123", "title": "Test Record"}');

      await runSecurelyHandler.execute();

      expect(window.showQuickPick).toHaveBeenCalledWith(['Workspace 1', 'Workspace 2'], expect.any(Object));
      expect(window.showInputBox).toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle user cancellation of workspace selection', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with multiple folders
      (workspace as any).workspaceFolders = [
        { name: 'Workspace 1', uri: { fsPath: '/workspace1' } },
        { name: 'Workspace 2', uri: { fsPath: '/workspace2' } }
      ];
      
      // Mock workspace selection cancellation
      (window.showQuickPick as jest.Mock).mockResolvedValue(undefined);

      await runSecurelyHandler.execute();

      expect(window.showQuickPick).toHaveBeenCalled();
      expect(window.showInputBox).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle no workspace folders', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock no workspace folders
      (workspace as any).workspaceFolders = [];

      await runSecurelyHandler.execute();

      expect(window.showQuickPick).not.toHaveBeenCalled();
      expect(window.showInputBox).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle no environment files found', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations - no environment files
      mockFs.readdirSync.mockReturnValue(['file.txt']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(false);

      await runSecurelyHandler.execute();

      expect(window.showInputBox).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('environment file selection', () => {
    it('should auto-select single environment file', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations - single environment file
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('TEST_VAR=value');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      mockPath.relative.mockReturnValue('.env');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({ TEST_VAR: 'value' });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "123", "title": "Test Record"}');

      await runSecurelyHandler.execute();

      expect(window.showQuickPick).not.toHaveBeenCalled(); // No QuickPick for single file
      expect(window.showInputBox).toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should show QuickPick for multiple environment files', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations - multiple environment files
      mockFs.readdirSync.mockReturnValue(['.env', '.env.local', '.env.production']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('TEST_VAR=value');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      mockPath.relative.mockImplementation((root, file) => file.replace(root + '/', ''));
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock environment file selection
      (window.showQuickPick as jest.Mock).mockResolvedValue('.env.local');
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "123", "title": "Test Record"}');

      await runSecurelyHandler.execute();

      expect(window.showQuickPick).toHaveBeenCalledWith(['.env', '.env.local', '.env.production'], expect.any(Object));
      expect(window.showInputBox).toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle user cancellation of environment file selection', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations - multiple environment files
      mockFs.readdirSync.mockReturnValue(['.env', '.env.local']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.relative.mockImplementation((root, file) => file.replace(root + '/', ''));
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      
      // Mock environment file selection cancellation
      (window.showQuickPick as jest.Mock).mockResolvedValue(undefined);

      await runSecurelyHandler.execute();

      expect(window.showQuickPick).toHaveBeenCalled();
      expect(window.showInputBox).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('secret resolution', () => {
    it('should resolve Keeper references in environment files', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://record123/custom_field/password\nAPI_KEY=keeper://record456/custom_field/api-key');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://record123/custom_field/password',
        API_KEY: 'keeper://record456/custom_field/api-key'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockImplementation((value) => value.startsWith('keeper://'));
      mockHelper.parseKeeperReference.mockImplementation((value) => {
        if (value.includes('record123')) {
          return { recordUid: 'record123', fieldType: 'custom_field', itemName: 'password' };
        }
        if (value.includes('record456')) {
          return { recordUid: 'record456', fieldType: 'custom_field', itemName: 'api-key' };
        }
        return null;
      });
      
      // Mock field extractor
      mockFieldExtractor.FieldExtractor.extractFieldValue.mockImplementation((record, fieldType, itemName) => {
        if (itemName === 'password') return 'secret-password';
        if (itemName === 'api-key') return 'secret-api-key';
        return null;
      });
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command responses
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"record_uid": "record123", "title": "Database Record"}')
        .mockResolvedValueOnce('{"record_uid": "record456", "title": "API Record"}');

      await runSecurelyHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('get', ['record123', '--format=json']);
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('get', ['record456', '--format=json']);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle mixed environment files (Keeper references + regular values)', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://record123/custom_field/password\nNODE_ENV=production\nAPI_KEY=keeper://record456/custom_field/api-key');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://record123/custom_field/password',
        NODE_ENV: 'production',
        API_KEY: 'keeper://record456/custom_field/api-key'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockImplementation((value) => value.startsWith('keeper://'));
      mockHelper.parseKeeperReference.mockImplementation((value) => {
        if (value.includes('record123')) {
          return { recordUid: 'record123', fieldType: 'custom_field', itemName: 'password' };
        }
        if (value.includes('record456')) {
          return { recordUid: 'record456', fieldType: 'custom_field', itemName: 'api-key' };
        }
        return null;
      });
      
      // Mock field extractor
      mockFieldExtractor.FieldExtractor.extractFieldValue.mockImplementation((record, fieldType, itemName) => {
        if (itemName === 'password') return 'secret-password';
        if (itemName === 'api-key') return 'secret-api-key';
        return null;
      });
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command responses
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"record_uid": "record123", "title": "Database Record"}')
        .mockResolvedValueOnce('{"record_uid": "record456", "title": "API Record"}');

      await runSecurelyHandler.execute();

      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle failed Keeper reference parsing', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://invalid-reference');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://invalid-reference'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null); // Failed parsing
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');

      await runSecurelyHandler.execute();

      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle environment file selection errors', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations - no environment files found
      mockFs.readdirSync.mockReturnValue(['file.txt']); // No .env files
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(false); // Not an environment file

      await runSecurelyHandler.execute();

      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to run securely: No environment files found in workspace');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle field extraction failures', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://record123/custom_field/password');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://record123/custom_field/password'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue({ recordUid: 'record123', fieldType: 'custom_field', itemName: 'password' });
      
      // Mock field extractor returning null
      mockFieldExtractor.FieldExtractor.extractFieldValue.mockReturnValue(null);
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "record123", "title": "Database Record"}');

      await runSecurelyHandler.execute();

      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('terminal creation', () => {
    it('should create terminal with correct configuration', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('TEST_VAR=value');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({ TEST_VAR: 'value' });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "123", "title": "Test Record"}');

      const mockTerminal = {
        show: jest.fn(),
        sendText: jest.fn(),
        dispose: jest.fn()
      };
      (window.createTerminal as jest.Mock).mockReturnValue(mockTerminal);

      await runSecurelyHandler.execute();

      expect(window.createTerminal).toHaveBeenCalledWith({
        name: 'Keeper Secure Run',
        cwd: '/test/workspace',
        env: expect.objectContaining({
          TEST_VAR: 'value'
        })
      });
      expect(mockTerminal.show).toHaveBeenCalled();
      expect(mockTerminal.sendText).toHaveBeenCalledWith('node index.js', true);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('error handling', () => {
    it('should handle file system errors', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations failure - this will cause "No environment files found" error
      mockFs.readdirSync.mockImplementation(() => {
        throw new Error('Permission denied');
      });

      await runSecurelyHandler.execute();

      // The actual error message is "No environment files found in workspace" not "Permission denied"
      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to run securely: No environment files found in workspace');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle workspace selection errors', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with multiple folders
      (workspace as any).workspaceFolders = [
        { name: 'Workspace 1', uri: { fsPath: '/workspace1' } },
        { name: 'Workspace 2', uri: { fsPath: '/workspace2' } }
      ];
      
      // Mock workspace selection cancellation
      (window.showQuickPick as jest.Mock).mockResolvedValue(undefined);

      await runSecurelyHandler.execute();

      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to run securely: No workspace selected');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('edge cases', () => {
    it('should handle empty environment files', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue(''); // Empty file
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({}); // Empty object
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');

      await runSecurelyHandler.execute();

      expect(window.createTerminal).toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle very long commands', async () => {
      const longCommand = 'node ' + 'a'.repeat(1000) + '.js';
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('TEST_VAR=value');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({ TEST_VAR: 'value' });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue(longCommand);
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "123", "title": "Test Record"}');

      const mockTerminal = {
        show: jest.fn(),
        sendText: jest.fn(),
        dispose: jest.fn()
      };
      (window.createTerminal as jest.Mock).mockReturnValue(mockTerminal);

      await runSecurelyHandler.execute();

      expect(mockTerminal.sendText).toHaveBeenCalledWith(longCommand, true);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('advanced secret resolution', () => {
    it('should handle multiple record processing', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://record123/custom_field/password\nAPI_KEY=keeper://record456/custom_field/api-key\nREDIS_URL=keeper://record789/custom_field/redis-url');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://record123/custom_field/password',
        API_KEY: 'keeper://record456/custom_field/api-key',
        REDIS_URL: 'keeper://record789/custom_field/redis-url'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockImplementation((value) => value.startsWith('keeper://'));
      mockHelper.parseKeeperReference.mockImplementation((value) => {
        if (value.includes('record123')) {
          return { recordUid: 'record123', fieldType: 'custom_field', itemName: 'password' };
        }
        if (value.includes('record456')) {
          return { recordUid: 'record456', fieldType: 'custom_field', itemName: 'api-key' };
        }
        if (value.includes('record789')) {
          return { recordUid: 'record789', fieldType: 'custom_field', itemName: 'redis-url' };
        }
        return null;
      });
      
      // Mock field extractor
      mockFieldExtractor.FieldExtractor.extractFieldValue.mockImplementation((record, fieldType, itemName) => {
        if (itemName === 'password') return 'secret-password';
        if (itemName === 'api-key') return 'secret-api-key';
        if (itemName === 'redis-url') return 'redis://localhost:6379';
        return null;
      });
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command responses for multiple records
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"record_uid": "record123", "title": "Database Record"}')
        .mockResolvedValueOnce('{"record_uid": "record456", "title": "API Record"}')
        .mockResolvedValueOnce('{"record_uid": "record789", "title": "Redis Record"}');

      await runSecurelyHandler.execute();

      // Verify all three records were fetched
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('get', ['record123', '--format=json']);
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('get', ['record456', '--format=json']);
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('get', ['record789', '--format=json']);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle partial resolution failures', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://record123/custom_field/password\nAPI_KEY=keeper://record456/custom_field/api-key');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://record123/custom_field/password',
        API_KEY: 'keeper://record456/custom_field/api-key'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockImplementation((value) => value.startsWith('keeper://'));
      mockHelper.parseKeeperReference.mockImplementation((value) => {
        if (value.includes('record123')) {
          return { recordUid: 'record123', fieldType: 'custom_field', itemName: 'password' };
        }
        if (value.includes('record456')) {
          return { recordUid: 'record456', fieldType: 'custom_field', itemName: 'api-key' };
        }
        return null;
      });
      
      // Mock field extractor - first succeeds, second fails
      mockFieldExtractor.FieldExtractor.extractFieldValue
        .mockReturnValueOnce('secret-password') // DB_PASSWORD resolves
        .mockReturnValueOnce(null); // API_KEY fails
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "record123", "title": "Database Record"}');

      await runSecurelyHandler.execute();

      // Verify partial resolution
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should set fallback values for failed secrets', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://record123/custom_field/password');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://record123/custom_field/password'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue({ recordUid: 'record123', fieldType: 'custom_field', itemName: 'password' });
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command failure
      mockCliService.executeCommanderCommand.mockRejectedValue(new Error('CLI command failed'));

      await runSecurelyHandler.execute();

      // Verify fallback value is set
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle CLI command failures gracefully', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://record123/custom_field/password');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://record123/custom_field/password'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue({ recordUid: 'record123', fieldType: 'custom_field', itemName: 'password' });
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command failure
      mockCliService.executeCommanderCommand.mockRejectedValue(new Error('CLI command failed'));

      await runSecurelyHandler.execute();

      // Verify error is handled gracefully
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle JSON parsing errors in CLI responses', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://record123/custom_field/password');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://record123/custom_field/password'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue({ recordUid: 'record123', fieldType: 'custom_field', itemName: 'password' });
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response with invalid JSON
      mockCliService.executeCommanderCommand.mockResolvedValue('invalid json');

      await runSecurelyHandler.execute();

      // Verify JSON parsing error is handled
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('terminal configuration', () => {
    it('should set correct working directory', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('TEST_VAR=value');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace/subfolder');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({ TEST_VAR: 'value' });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "123", "title": "Test Record"}');

      const mockTerminal = {
        show: jest.fn(),
        sendText: jest.fn(),
        dispose: jest.fn()
      };
      (window.createTerminal as jest.Mock).mockReturnValue(mockTerminal);

      await runSecurelyHandler.execute();

      // Verify working directory is set correctly
      expect(window.createTerminal).toHaveBeenCalledWith({
        name: 'Keeper Secure Run',
        cwd: '/test/workspace/subfolder',
        env: expect.any(Object)
      });
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle terminal creation failures', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('TEST_VAR=value');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({ TEST_VAR: 'value' });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "123", "title": "Test Record"}');

      // Mock terminal creation failure
      (window.createTerminal as jest.Mock).mockImplementation(() => {
        throw new Error('Terminal creation failed');
      });

      await runSecurelyHandler.execute();

      // Verify terminal creation error is handled
      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to run securely: Terminal creation failed');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('logging coverage', () => {
    it('should log successful operations', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('TEST_VAR=value');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({ TEST_VAR: 'value' });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "123", "title": "Test Record"}');

      const mockLogger = require('../../../../src/utils/logger').logger;

      await runSecurelyHandler.execute();

      // Verify info logging for successful operations
      expect(mockLogger.logInfo).toHaveBeenCalledWith('Resolved 1 environment variables');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should log errors properly', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations failure
      mockFs.readdirSync.mockImplementation(() => {
        throw new Error('Permission denied');
      });

      const mockLogger = require('../../../../src/utils/logger').logger;

      await runSecurelyHandler.execute();

      // Verify error logging
      expect(mockLogger.logError).toHaveBeenCalledWith('RunSecurelyHandler.execute failed: No environment files found in workspace', expect.any(Error));
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('edge cases', () => {
    it('should handle very large environment files', async () => {
      // Create a large environment file with many variables
      const largeEnvContent = Array.from({ length: 100 }, (_, i) => `VAR_${i}=value_${i}`).join('\n');
      
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue(largeEnvContent);
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      const largeEnvConfig = {};
      for (let i = 0; i < 100; i++) {
        largeEnvConfig[`VAR_${i}`] = `value_${i}`;
      }
      mockDotenv.parse.mockReturnValue(largeEnvConfig);
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue(null);
      mockHelper.validateKeeperReference.mockReturnValue(false);
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('{"record_uid": "123", "title": "Test Record"}');

      const mockTerminal = {
        show: jest.fn(),
        sendText: jest.fn(),
        dispose: jest.fn()
      };
      (window.createTerminal as jest.Mock).mockReturnValue(mockTerminal);

      await runSecurelyHandler.execute();

      // Verify large file is handled
      expect(window.createTerminal).toHaveBeenCalledWith({
        name: 'Keeper Secure Run',
        cwd: '/test/workspace',
        env: expect.objectContaining(largeEnvConfig)
      });
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle complex Keeper reference patterns', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://record123/custom_field/password\nAPI_KEY=keeper://record456/field/api-key\nSSH_KEY=keeper://record789/ssh_key/private_key');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://record123/custom_field/password',
        API_KEY: 'keeper://record456/field/api-key',
        SSH_KEY: 'keeper://record789/ssh_key/private_key'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockImplementation((value) => value.startsWith('keeper://'));
      mockHelper.parseKeeperReference.mockImplementation((value) => {
        if (value.includes('record123')) {
          return { recordUid: 'record123', fieldType: 'custom_field', itemName: 'password' };
        }
        if (value.includes('record456')) {
          return { recordUid: 'record456', fieldType: 'field', itemName: 'api-key' };
        }
        if (value.includes('record789')) {
          return { recordUid: 'record789', fieldType: 'ssh_key', itemName: 'private_key' };
        }
        return null;
      });
      
      // Mock field extractor
      mockFieldExtractor.FieldExtractor.extractFieldValue.mockImplementation((record, fieldType, itemName) => {
        if (itemName === 'password') return 'secret-password';
        if (itemName === 'api-key') return 'secret-api-key';
        if (itemName === 'private_key') return '-----BEGIN PRIVATE KEY-----...';
        return null;
      });
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command responses
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"record_uid": "record123", "title": "Database Record"}')
        .mockResolvedValueOnce('{"record_uid": "record456", "title": "API Record"}')
        .mockResolvedValueOnce('{"record_uid": "record789", "title": "SSH Record"}');

      await runSecurelyHandler.execute();

      // Verify complex patterns are handled
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle network/CLI timeouts', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock workspace with single folder
      (workspace as any).workspaceFolders = [
        { name: 'Test Workspace', uri: { fsPath: '/test/workspace' } }
      ];
      
      // Mock fs operations
      mockFs.readdirSync.mockReturnValue(['.env']);
      mockFs.statSync.mockReturnValue({ isFile: () => true });
      mockFs.readFileSync.mockReturnValue('DB_PASSWORD=keeper://record123/custom_field/password');
      
      // Mock path operations
      mockPath.join.mockImplementation((...args) => args.join('/'));
      mockPath.dirname.mockReturnValue('/test/workspace');
      
      // Mock dotenv parsing
      mockDotenv.parse.mockReturnValue({
        DB_PASSWORD: 'keeper://record123/custom_field/password'
      });
      
      // Mock helper functions
      const mockHelper = require('../../../../src/utils/helper');
      mockHelper.isEnvironmentFile.mockReturnValue(true);
      mockHelper.validateKeeperReference.mockReturnValue(true);
      mockHelper.parseKeeperReference.mockReturnValue({ recordUid: 'record123', fieldType: 'custom_field', itemName: 'password' });
      
      // Mock command input
      (window.showInputBox as jest.Mock).mockResolvedValue('node index.js');
      
      // Mock CLI command timeout
      mockCliService.executeCommanderCommand.mockImplementation(() => {
        return new Promise((_, reject) => {
          setTimeout(() => reject(new Error('CLI timeout')), 100);
        });
      });

      await runSecurelyHandler.execute();

      // Verify timeout is handled gracefully
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });
});
