import { ExtensionContext } from 'vscode';
import { CliService } from '../../../../src/services/cli';
import { StorageManager } from '../../../../src/commands/storage/storageManager';
import { StatusBarSpinner } from '../../../../src/utils/helper';
import { logger } from '../../../../src/utils/logger';
import { safeJsonParse } from '../../../../src/utils/helper';

// Mock dependencies
jest.mock('../../../../src/services/cli');
jest.mock('../../../../src/utils/helper', () => ({
  resolveFolderPaths: jest.fn(),
  safeJsonParse: jest.fn()
}));
jest.mock('../../../../src/utils/logger');
jest.mock('vscode', () => ({
  ...jest.requireActual('vscode'),
  window: {
    showQuickPick: jest.fn(),
    showWarningMessage: jest.fn(),
    showInformationMessage: jest.fn(),
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

describe('StorageManager', () => {
  let mockContext: ExtensionContext;
  let mockCliService: jest.Mocked<CliService>;
  let mockSpinner: jest.Mocked<StatusBarSpinner>;
  let storageManager: StorageManager;
  let mockResolveFolderPaths: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockContext = {
      workspaceState: {
        get: jest.fn(), // This creates a proper Jest mock function
        update: jest.fn()
      },
      subscriptions: []
    } as unknown as ExtensionContext;

    mockCliService = {
      executeCommanderCommand: jest.fn()
    } as unknown as jest.Mocked<CliService>;

    mockSpinner = {
      show: jest.fn(),
      hide: jest.fn(),
      dispose: jest.fn()
    } as unknown as jest.Mocked<StatusBarSpinner>;

    // Get the mocked resolveFolderPaths function
    mockResolveFolderPaths = require('../../../../src/utils/helper').resolveFolderPaths;

    storageManager = new StorageManager(mockContext, mockCliService, mockSpinner);
  });

  describe('constructor', () => {
    it('should initialize storage manager', () => {
      expect(logger.logDebug).toHaveBeenCalledWith('StorageManager initialized');
    });
  });

  describe('getCurrentStorage', () => {
    it('should get current storage from workspace state', () => {
      const mockStorage = { folderUid: '/', name: 'My Vault', parentUid: '/', folderPath: '/' };
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(mockStorage);

      const result = storageManager.getCurrentStorage();

      expect(mockContext.workspaceState.get).toHaveBeenCalledWith('currentStorage', null);
      expect(result).toEqual(mockStorage);
      expect(logger.logDebug).toHaveBeenCalledWith('Retrieved current storage: {"folderUid":"/","name":"My Vault","parentUid":"/","folderPath":"/"}');
    });

    it('should return null when no storage is set', () => {
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(null);

      const result = storageManager.getCurrentStorage();

      expect(result).toBeNull();
      expect(logger.logDebug).toHaveBeenCalledWith('Retrieved current storage: null');
    });
  });

  describe('setCurrentStorage', () => {
    it('should set current storage in workspace state', () => {
      const mockStorage = { folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' };

      storageManager.setCurrentStorage(mockStorage);

      expect(mockContext.workspaceState.update).toHaveBeenCalledWith('currentStorage', mockStorage);
      expect(logger.logDebug).toHaveBeenCalledWith('Setting current storage to: {"folderUid":"123","name":"Test Folder","parentUid":"/","folderPath":"/Test Folder"}');
    });

    it('should set storage to null', () => {
      storageManager.setCurrentStorage(null);

      expect(mockContext.workspaceState.update).toHaveBeenCalledWith('currentStorage', null);
      expect(logger.logDebug).toHaveBeenCalledWith('Setting current storage to: null');
    });
  });

  describe('validateCurrentStorage', () => {
    it('should validate My Vault storage successfully', async () => {
      const mockStorage = { folderUid: '/', name: 'My Vault', parentUid: '/', folderPath: '/' };
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(mockStorage);

      const result = await storageManager.validateCurrentStorage();

      expect(result).toBe(true);
      expect(mockSpinner.show).toHaveBeenCalledWith('Validating storage...');
      // My Vault case returns early, so spinner.hide is not called
      expect(mockSpinner.hide).not.toHaveBeenCalled();
      expect(logger.logDebug).toHaveBeenCalledWith('Current storage is My Vault, validation successful');
    });

    it('should validate existing folder storage successfully', async () => {
      // Mock current storage to be a folder (not My Vault)
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue({
        folderUid: 'folder123',
        name: 'Test Folder',
        parentUid: '/',
        folderPath: '/Test Folder'
      });
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('valid json response');
      
      // Mock safeJsonParse to return valid folder data that matches current storage
      (safeJsonParse as jest.Mock).mockReturnValue([
        { folder_uid: 'folder123', name: 'Test Folder', parent_uid: '/' }
      ]);

      const result = await storageManager.validateCurrentStorage();

      expect(result).toBe(true);
      expect(safeJsonParse).toHaveBeenCalledWith('valid json response', []);
    });

    it('should fail validation when folder no longer exists', async () => {
      const mockStorage = { folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' };
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(mockStorage);
      
      const mockFolders = [{ folder_uid: '456', name: 'Other Folder' }];
      mockCliService.executeCommanderCommand.mockResolvedValue(JSON.stringify(mockFolders));

      // Mock safeJsonParse to return different folder data
      (safeJsonParse as jest.Mock).mockReturnValue([
        { folder_uid: 'different123', name: 'Different Folder', parent_uid: '/' }
      ]);

      const result = await storageManager.validateCurrentStorage();

      expect(result).toBe(false);
      expect(mockContext.workspaceState.update).toHaveBeenCalledWith('currentStorage', null);
      expect(logger.logError).toHaveBeenCalledWith('Folder "Test Folder" no longer exists on Keeper vault');
      // Folder not found case returns early, so spinner.hide is not called
      expect(mockSpinner.hide).not.toHaveBeenCalled();
      expect(safeJsonParse).toHaveBeenCalledWith(JSON.stringify(mockFolders), []);
    });

    it('should fail validation when no current storage exists', async () => {
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(null);

      const result = await storageManager.validateCurrentStorage();

      expect(result).toBe(false);
      // No current storage case returns early, so spinner.hide is not called
      expect(mockSpinner.hide).not.toHaveBeenCalled();
    });
  });

  describe('ensureValidStorage', () => {
    it('should choose folder when no current storage exists', async () => {
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(null);
      
      // Mock chooseFolder method
      const chooseFolderSpy = jest.spyOn(storageManager, 'chooseFolder').mockResolvedValue();

      await storageManager.ensureValidStorage();

      expect(chooseFolderSpy).toHaveBeenCalled();
    });

    it('should validate existing storage successfully', async () => {
      const mockStorage = { folderUid: '/', name: 'My Vault', parentUid: '/', folderPath: '/' };
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(mockStorage);
      
      // Mock validateCurrentStorage method
      const validateSpy = jest.spyOn(storageManager, 'validateCurrentStorage').mockResolvedValue(true);

      await storageManager.ensureValidStorage();

      expect(validateSpy).toHaveBeenCalled();
    });

    it('should prompt for new folder when validation fails', async () => {
      const mockStorage = { folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' };
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(mockStorage);
      
      // Mock validateCurrentStorage method
      const validateSpy = jest.spyOn(storageManager, 'validateCurrentStorage').mockResolvedValue(false);
      const chooseFolderSpy = jest.spyOn(storageManager, 'chooseFolder').mockResolvedValue();
      
      const { window } = require('vscode');
      (window.showWarningMessage as jest.Mock).mockResolvedValue('Yes');

      await storageManager.ensureValidStorage();

      expect(validateSpy).toHaveBeenCalled();
      expect(window.showWarningMessage).toHaveBeenCalledWith(
        'Previously selected folder is no longer available. Would you like to choose a new folder?',
        'Yes', 'No'
      );
      expect(chooseFolderSpy).toHaveBeenCalled();
    });

    it('should not choose new folder when user declines', async () => {
      const mockStorage = { folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' };
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(mockStorage);
      
      // Mock validateCurrentStorage method
      const validateSpy = jest.spyOn(storageManager, 'validateCurrentStorage').mockResolvedValue(false);
      const chooseFolderSpy = jest.spyOn(storageManager, 'chooseFolder').mockResolvedValue();
      
      const { window } = require('vscode');
      (window.showWarningMessage as jest.Mock).mockResolvedValue('No');

      await storageManager.ensureValidStorage();

      expect(validateSpy).toHaveBeenCalled();
      expect(chooseFolderSpy).not.toHaveBeenCalled();
    });
  });

  describe('chooseFolder', () => {
    it('should choose folder successfully', async () => {
      const mockFolders = [{ folder_uid: '123', name: 'Test Folder' }];
      mockCliService.executeCommanderCommand.mockResolvedValue(JSON.stringify(mockFolders));
      
      // Mock resolveFolderPaths to return a folder with path
      mockResolveFolderPaths.mockReturnValue([
        { folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' }
      ]);
      
      const { window } = require('vscode');
      const mockSelectedFolder = { label: 'Test Folder', value: '123' };
      (window.showQuickPick as jest.Mock).mockResolvedValue(mockSelectedFolder);

      await storageManager.chooseFolder();

      expect(mockCliService.executeCommanderCommand).toHaveBeenCalledWith('ls', ['--format=json', '-f', '-R']);
      expect(mockSpinner.show).toHaveBeenCalledWith('Retrieving folders...');
      expect(mockSpinner.hide).toHaveBeenCalled();
      expect(window.showQuickPick).toHaveBeenCalled();
      expect(window.showInformationMessage).toHaveBeenCalledWith('Storage location set to "Test Folder" folder');
    });

    it('should handle no folder selection', async () => {
      const mockFolders = [{ folder_uid: '123', name: 'Test Folder' }];
      mockCliService.executeCommanderCommand.mockResolvedValue(JSON.stringify(mockFolders));
      
      // Mock resolveFolderPaths to return a folder with path
      mockResolveFolderPaths.mockReturnValue([
        { folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' }
      ]);
      
      const { window } = require('vscode');
      (window.showQuickPick as jest.Mock).mockResolvedValue(undefined);

      await storageManager.chooseFolder();

      expect(window.showQuickPick).toHaveBeenCalled();
      expect(window.showInformationMessage).not.toHaveBeenCalled();
    });

    it('should handle CLI command failure', async () => {
      mockCliService.executeCommanderCommand.mockRejectedValue(new Error('CLI command failed'));

      await expect(storageManager.chooseFolder()).rejects.toThrow('CLI command failed');
    });
  });

  describe('error handling', () => {
    it('should handle JSON parsing errors in CLI response', async () => {
      const mockStorage = { folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' };
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(mockStorage);
      
      // Mock CLI command response with invalid JSON
      mockCliService.executeCommanderCommand.mockResolvedValue('invalid json');

      // Mock safeJsonParse to throw error
      (safeJsonParse as jest.Mock).mockImplementation(() => {
        throw new Error('Unexpected token \'i\', "invalid json" is not valid JSON');
      });

      await expect(storageManager.validateCurrentStorage()).rejects.toThrow(
        'Unexpected token \'i\', "invalid json" is not valid JSON'
      );
    });

    it('should handle CLI command failures during validation', async () => {
      const mockStorage = { folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' };
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(mockStorage);
      
      // Mock CLI command failure
      mockCliService.executeCommanderCommand.mockRejectedValue(new Error('CLI command failed'));

      await expect(storageManager.validateCurrentStorage()).rejects.toThrow('CLI command failed');
    });

    it('should handle CLI command failures during folder selection', async () => {
      // Mock CLI command failure
      mockCliService.executeCommanderCommand.mockRejectedValue(new Error('CLI command failed'));

      await expect(storageManager.chooseFolder()).rejects.toThrow('CLI command failed');
    });
  });

  describe('edge cases', () => {
    it('should handle empty folder list from CLI', async () => {
      // Mock current storage to be a folder (not My Vault)
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue({
        folderUid: 'folder123',
        name: 'Test Folder',
        parentUid: '/',
        folderPath: '/Test Folder'
      });
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('[]');
      
      // Mock safeJsonParse to return empty array
      (safeJsonParse as jest.Mock).mockReturnValue([]);

      const result = await storageManager.validateCurrentStorage();

      expect(result).toBe(false);
      expect(mockContext.workspaceState.update).toHaveBeenCalledWith('currentStorage', null);
      expect(safeJsonParse).toHaveBeenCalledWith('[]', []);
    });

    it('should handle malformed folder data', async () => {
      // Mock current storage to be a folder (not My Vault)
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue({
        folderUid: 'folder123',
        name: 'Test Folder',
        parentUid: '/',
        folderPath: '/Test Folder'
      });
      
      // Mock CLI command response
      mockCliService.executeCommanderCommand.mockResolvedValue('[{"invalid": "data"}]');
      
      // Mock safeJsonParse to return malformed data
      (safeJsonParse as jest.Mock).mockReturnValue([
        { invalid: 'data' }
      ]);

      const result = await storageManager.validateCurrentStorage();

      expect(result).toBe(false);
      expect(mockContext.workspaceState.update).toHaveBeenCalledWith('currentStorage', null);
      expect(safeJsonParse).toHaveBeenCalledWith('[{"invalid": "data"}]', []);
    });
  });

  describe('logging coverage', () => {

    it('should log errors properly', async () => {
      const mockStorage = { folderUid: '123', name: 'Test Folder', parentUid: '/', folderPath: '/Test Folder' };
      (mockContext.workspaceState.get as jest.Mock).mockReturnValue(mockStorage);
      
      const mockFolders = [{ folder_uid: '456', name: 'Other Folder' }];
      mockCliService.executeCommanderCommand.mockResolvedValue(JSON.stringify(mockFolders));

      // Mock safeJsonParse to return different folder data
      (safeJsonParse as jest.Mock).mockReturnValue([
        { folder_uid: 'different123', name: 'Different Folder', parent_uid: '/' }
      ]);

      const mockLogger = require('../../../../src/utils/logger').logger;

      await storageManager.validateCurrentStorage();

      // Verify error logging
      expect(mockLogger.logError).toHaveBeenCalledWith('Folder "Test Folder" no longer exists on Keeper vault');
    });
  });
}); 