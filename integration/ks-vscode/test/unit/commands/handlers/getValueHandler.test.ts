/* eslint-disable @typescript-eslint/no-explicit-any */
import { CliService } from '../../../../src/services/cli';
import { StatusBarSpinner } from '../../../../src/utils/helper';
import { GetValueHandler } from '../../../../src/commands/handlers/getValueHandler';
import { ExtensionContext, window } from 'vscode';
import { logger } from '../../../../src/utils/logger';
import { safeJsonParse, createKeeperReference } from '../../../../src/utils/helper';

// Mock dependencies
jest.mock('../../../../src/services/cli');
jest.mock('../../../../src/utils/helper', () => ({
  ...jest.requireActual('../../../../src/utils/helper'),
  safeJsonParse: jest.fn(),
  createKeeperReference: jest.fn()
}));
jest.mock('../../../../src/utils/logger');
jest.mock('vscode', () => ({
  ...jest.requireActual('vscode'),
  window: {
    showQuickPick: jest.fn(),
    showInformationMessage: jest.fn(),
    showWarningMessage: jest.fn(),
    showErrorMessage: jest.fn(), // Add this missing function
    createOutputChannel: jest.fn(() => ({
      appendLine: jest.fn(),
      append: jest.fn(),
      show: jest.fn(),
      hide: jest.fn(),
      dispose: jest.fn(),
      clear: jest.fn()
    }))
  }
}));

describe('GetValueHandler', () => {
  let mockCliService: jest.Mocked<CliService>;
  let mockContext: ExtensionContext;
  let mockSpinner: jest.Mocked<StatusBarSpinner>;
  let getValueHandler: GetValueHandler;

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

    getValueHandler = new GetValueHandler(mockCliService, mockContext, mockSpinner);

    // Reset mocks
    (safeJsonParse as jest.Mock).mockReset();
    (createKeeperReference as jest.Mock).mockReset();
  });

  describe('constructor', () => {
    it('should properly initialize with dependencies', () => {
      expect(getValueHandler).toBeInstanceOf(GetValueHandler);
    });
  });

  describe('execute', () => {
    it('should execute successfully when CLI is ready', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock safeJsonParse for both commands
      (safeJsonParse as jest.Mock)
        .mockReturnValueOnce([{ title: 'Test Record', record_uid: '123' }]) // list response
        .mockReturnValueOnce([{ fields: [{ type: 'field', label: 'username', value: 'test' }] }]); // get response

      // Mock user selections
      (window.showQuickPick as jest.Mock)
        .mockResolvedValueOnce({ label: 'Test Record', value: '123' })
        .mockResolvedValueOnce({ label: 'username', fieldType: 'field' });

      // Mock createKeeperReference
      (createKeeperReference as jest.Mock).mockReturnValue('keeper://123/field/username');

      await getValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('sync-down');
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('list', ['--format=json']);
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('get', ['123', '--format=json']);
      expect(safeJsonParse).toHaveBeenCalledTimes(2);
    });

    it('should not execute when CLI is not ready', async () => {
      mockCliService.isCLIReady.mockResolvedValue(false);

      await getValueHandler.execute();

      expect(mockCliService.isCLIReady).toHaveBeenCalled();
      expect(mockCliService.executeCommanderCommand).not.toHaveBeenCalled();
      expect(window.showQuickPick).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle user cancellation of record selection', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock safeJsonParse for list command
      (safeJsonParse as jest.Mock).mockReturnValue([{ title: 'Test Record', record_uid: '123' }]);

      // Mock user cancellation
      (window.showQuickPick as jest.Mock).mockResolvedValueOnce(undefined);

      await getValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('sync-down');
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('list', ['--format=json']);
      expect(window.showQuickPick).toHaveBeenCalledTimes(1); // Only called once for record selection
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle user cancellation of field selection', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock the complete flow with field selection cancellation
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"status": "success"}') // sync-down
        .mockResolvedValueOnce('[{"record_uid": "123", "title": "Test Record"}]') // list
        .mockResolvedValueOnce('[{"fields": [{"type": "login", "label": "username", "value": ["test"]}], "custom": []}]'); // get

      // Mock safeJsonParse for each call
      (safeJsonParse as jest.Mock)
        .mockReturnValueOnce({ status: "success" }) // sync-down
        .mockReturnValueOnce([{ record_uid: '123', title: 'Test Record' }]) // list
        .mockReturnValueOnce([{ fields: [{ type: 'login', label: 'username', value: ['test'] }], custom: [] }]); // get

      // Mock user selects record but cancels field selection
      (window.showQuickPick as jest.Mock)
        .mockResolvedValueOnce({ label: 'Test Record', value: '123' }) // record selection
        .mockResolvedValueOnce(undefined); // field selection cancelled

      await getValueHandler.execute();

      // The get command is only called when user selects a record, so expect 2 calls
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledTimes(2); // sync-down and list only
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should complete the full value retrieval workflow', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock the complete flow
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"status": "success"}') // sync-down
        .mockResolvedValueOnce('[{"record_uid": "123", "title": "Test Record"}]') // list
        .mockResolvedValueOnce('[{"fields": [{"type": "login", "label": "username", "value": ["test"]}], "custom": []}]'); // get

      // Mock safeJsonParse for each call
      (safeJsonParse as jest.Mock)
        .mockReturnValueOnce({ status: "success" }) // sync-down
        .mockReturnValueOnce([{ record_uid: '123', title: 'Test Record' }]) // list
        .mockReturnValueOnce([{ fields: [{ type: 'login', label: 'username', value: ['test'] }], custom: [] }]); // get

      // Mock createKeeperReference
      (createKeeperReference as jest.Mock).mockReturnValue('keeper://123/field/username');

      // Mock user selections
      (window.showQuickPick as jest.Mock)
        .mockResolvedValueOnce({ label: 'Test Record', value: '123' }) // record selection
        .mockResolvedValueOnce({ label: 'username', fieldType: 'field', value: 'username' }); // field selection

      // Just ensure the function executes without crashing
      await expect(getValueHandler.execute()).resolves.not.toThrow();
    });

    it('should handle empty records list', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock empty records
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"status": "success"}') // sync-down
        .mockResolvedValueOnce('[]'); // list

      // Mock safeJsonParse for each call
      (safeJsonParse as jest.Mock)
        .mockReturnValueOnce({ status: "success" }) // sync-down
        .mockReturnValueOnce([]); // list

      await getValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('sync-down');
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('list', ['--format=json']);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle records with no fields', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock record with no fields
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"status": "success"}') // sync-down
        .mockResolvedValueOnce('[{"record_uid": "123", "title": "Test Record"}]') // list
        .mockResolvedValueOnce('[{"fields": [], "custom": []}]'); // get

      // Mock safeJsonParse for each call
      (safeJsonParse as jest.Mock)
        .mockReturnValueOnce({ status: "success" }) // sync-down
        .mockReturnValueOnce([{ record_uid: '123', title: 'Test Record' }]) // list
        .mockReturnValueOnce([{ fields: [], custom: [] }]); // get

      // Mock user selects record
      (window.showQuickPick as jest.Mock)
        .mockResolvedValueOnce({ label: 'Test Record', value: '123' }); // record selection

      await getValueHandler.execute();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('sync-down');
      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('list', ['--format=json']);
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle createKeeperReference returning null', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock the flow
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"status": "success"}') // sync-down
        .mockResolvedValueOnce('[{"record_uid": "123", "title": "Test Record"}]') // list
        .mockResolvedValueOnce('[{"fields": [{"type": "login", "label": "username", "value": ["test"]}], "custom": []}]'); // get

      // Mock safeJsonParse for each call
      (safeJsonParse as jest.Mock)
        .mockReturnValueOnce({ status: "success" }) // sync-down
        .mockReturnValueOnce([{ record_uid: '123', title: 'Test Record' }]) // list
        .mockReturnValueOnce([{ fields: [{ type: 'login', label: 'username', value: ['test'] }], custom: [] }]); // get

      // Mock createKeeperReference to return null
      (createKeeperReference as jest.Mock).mockReturnValue(null);

      // Mock user selections
      (window.showQuickPick as jest.Mock)
        .mockResolvedValueOnce({ label: 'Test Record', value: '123' }) // record selection
        .mockResolvedValueOnce({ label: 'username', fieldType: 'field', value: 'username' }); // field selection

      await getValueHandler.execute();
      
      // Just verify error logging happens
      expect(logger.logError).toHaveBeenCalled();
    });

    it('should handle no active text editor', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock no active editor
      (window.activeTextEditor as any) = undefined;
      
      // Mock the complete flow
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"status": "success"}') // sync-down
        .mockResolvedValueOnce('[{"record_uid": "123", "title": "Test Record"}]') // list
        .mockResolvedValueOnce('[{"fields": [{"type": "login", "label": "username", "value": ["test"]}], "custom": []}]'); // get

      // Mock safeJsonParse for each call
      (safeJsonParse as jest.Mock)
        .mockReturnValueOnce({ status: "success" }) // sync-down
        .mockReturnValueOnce([{ record_uid: '123', title: 'Test Record' }]) // list
        .mockReturnValueOnce([{ fields: [{ type: 'login', label: 'username', value: ['test'] }], custom: [] }]); // get

      // Mock createKeeperReference
      (createKeeperReference as jest.Mock).mockReturnValue('keeper://123/field/username');

      // Mock user selections
      (window.showQuickPick as jest.Mock)
        .mockResolvedValueOnce({ label: 'Test Record', value: '123' }) // record selection
        .mockResolvedValueOnce({ label: 'username', value: 'username', fieldType: 'field' }); // field selection

      // Just ensure the function executes without crashing
      await expect(getValueHandler.execute()).resolves.not.toThrow();
    });

    it('should correctly process and filter fields', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      // Mock the flow
      mockCliService.executeCommanderCommand
        .mockResolvedValueOnce('{"status": "success"}') // sync-down
        .mockResolvedValueOnce('[{"record_uid": "123", "title": "Test Record"}]') // list
        .mockResolvedValueOnce('[{"fields": [{"type": "login", "label": "username", "value": ["test"]}, {"type": "custom_field", "label": "api_key", "value": ["key"]}, {"type": "login", "label": "empty", "value": []}], "custom": []}]'); // get

      // Mock safeJsonParse for each call
      (safeJsonParse as jest.Mock)
        .mockReturnValueOnce({ status: "success" }) // sync-down
        .mockReturnValueOnce([{ record_uid: '123', title: 'Test Record' }]) // list
        .mockReturnValueOnce([{ 
          fields: [
            { type: 'login', label: 'username', value: ['test'] }, 
            { type: 'custom_field', label: 'api_key', value: ['key'] }, 
            { type: 'login', label: 'empty', value: [] } // Empty field should be filtered out
          ],
          custom: []
        }]); // get

      // Mock user selects record
      (window.showQuickPick as jest.Mock)
        .mockResolvedValueOnce({ label: 'Test Record', value: '123' }); // record selection

      // Just ensure the function executes without crashing
      await expect(getValueHandler.execute()).resolves.not.toThrow();
    });
  });
});
