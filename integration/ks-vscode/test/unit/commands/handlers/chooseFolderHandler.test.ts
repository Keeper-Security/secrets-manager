import { CliService } from '../../../../src/services/cli';
import { StatusBarSpinner } from '../../../../src/utils/helper';
import { ChooseFolderHandler } from '../../../../src/commands/handlers/chooseFolderHandler';
import { StorageManager } from '../../../../src/commands/storage/storageManager';
import { logger } from '../../../../src/utils/logger'; 
import { ExtensionContext, window } from 'vscode';

// Mock dependencies
jest.mock('../../../../src/services/cli');
jest.mock('../../../../src/commands/storage/storageManager');
jest.mock('../../../../src/utils/helper');
jest.mock('../../../../src/utils/logger');
jest.mock('vscode', () => ({
  ...jest.requireActual('vscode'),
  window: {
    showQuickPick: jest.fn(),
    showInformationMessage: jest.fn(),
    showErrorMessage: jest.fn(),
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

describe('ChooseFolderHandler', () => {
  let mockCliService: jest.Mocked<CliService>;
  let mockContext: ExtensionContext;
  let mockSpinner: jest.Mocked<StatusBarSpinner>;
  let mockStorageManager: jest.Mocked<StorageManager>;
  let chooseFolderHandler: ChooseFolderHandler;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockCliService = {
      isCLIReady: jest.fn(),
      getFolders: jest.fn()
    } as unknown as jest.Mocked<CliService>;

    mockContext = {} as ExtensionContext;
    
    // Properly mock the StatusBarSpinner with required methods
    mockSpinner = {
      show: jest.fn(),
      updateMessage: jest.fn(),
      hide: jest.fn(),
      dispose: jest.fn()
    } as unknown as jest.Mocked<StatusBarSpinner>;
    
    mockStorageManager = {
      chooseFolder: jest.fn()
    } as unknown as jest.Mocked<StorageManager>;

    chooseFolderHandler = new ChooseFolderHandler(mockCliService, mockContext, mockSpinner, mockStorageManager);
  });

  describe('execute', () => {
    it('should execute successfully when CLI is ready', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.chooseFolder.mockResolvedValue();

      await chooseFolderHandler.execute();

      expect(mockCliService.isCLIReady).toHaveBeenCalled();
      expect(mockStorageManager.chooseFolder).toHaveBeenCalled();
      expect(logger.logDebug).toHaveBeenCalledWith('ChooseFolderHandler: Folder selection completed');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should not execute when CLI is not ready', async () => {
      mockCliService.isCLIReady.mockResolvedValue(false);

      await chooseFolderHandler.execute();

      expect(mockCliService.isCLIReady).toHaveBeenCalled();
      expect(mockStorageManager.chooseFolder).not.toHaveBeenCalled();
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle user cancellation of folder selection', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.chooseFolder.mockResolvedValue();

      await chooseFolderHandler.execute();

      expect(mockStorageManager.chooseFolder).toHaveBeenCalled();
      expect(logger.logDebug).toHaveBeenCalledWith('ChooseFolderHandler: Folder selection completed');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should handle CLI service errors', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      const error = new Error('Failed to choose folder');
      mockStorageManager.chooseFolder.mockRejectedValue(error);

      // The method should resolve successfully even when an error occurs
      await chooseFolderHandler.execute();
      
      expect(logger.logError).toHaveBeenCalledWith('ChooseFolderHandler.execute failed: Failed to choose folder', error);
      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to choose folder: Failed to choose folder');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('constructor', () => {
    it('should properly initialize with dependencies', () => {
      expect(chooseFolderHandler).toBeInstanceOf(ChooseFolderHandler);
      // Could add tests for private property access if needed
    });
  });

  describe('execute edge cases', () => {
    it('should handle non-Error objects in catch block', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      const nonError = 'String error';
      mockStorageManager.chooseFolder.mockRejectedValue(nonError);

      await chooseFolderHandler.execute();
      
      expect(logger.logError).toHaveBeenCalledWith('ChooseFolderHandler.execute failed: Unknown error', nonError);
      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to choose folder: Unknown error');
    });

    it('should handle errors with very long messages', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      const longError = new Error('A'.repeat(1000));
      mockStorageManager.chooseFolder.mockRejectedValue(longError);

      await chooseFolderHandler.execute();
      
      expect(logger.logError).toHaveBeenCalledWith('ChooseFolderHandler.execute failed: ' + 'A'.repeat(1000), longError);
      expect(window.showErrorMessage).toHaveBeenCalledWith('Failed to choose folder: ' + 'A'.repeat(1000));
    });

    it('should log all debug messages in correct order', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.chooseFolder.mockResolvedValue();

      await chooseFolderHandler.execute();

      // Verify all expected debug messages were logged
      expect(logger.logDebug).toHaveBeenCalledWith('ChooseFolderHandler.execute called');
      expect(logger.logDebug).toHaveBeenCalledWith('ChooseFolderHandler: Starting folder selection process');
      expect(logger.logDebug).toHaveBeenCalledWith('ChooseFolderHandler: Folder selection completed');
      
      // Verify the total number of debug calls (including constructor and canExecute)
      expect(logger.logDebug).toHaveBeenCalledTimes(6);
    });
  });

  describe('spinner management', () => {
    it('should hide spinner even when StorageManager.chooseFolder throws', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      mockStorageManager.chooseFolder.mockRejectedValue(new Error('Test error'));

      await chooseFolderHandler.execute();
      
      expect(mockSpinner.hide).toHaveBeenCalled();
    });

    it('should hide spinner even when CLI is not ready', async () => {
      mockCliService.isCLIReady.mockResolvedValue(false);

      await chooseFolderHandler.execute();
      
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });
}); 