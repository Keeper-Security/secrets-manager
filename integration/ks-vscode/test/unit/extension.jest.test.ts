import { activate, deactivate } from '../../src/extension';
import { configuration } from '../../src/services/configurations';
import { Core } from '../../src/services/core';
import { logger } from '../../src/utils/logger';
import * as vscode from 'vscode';

// Mock dependencies
jest.mock('../../src/services/configurations');
jest.mock('../../src/services/core');
jest.mock('../../src/utils/logger');
jest.mock('../../src/utils/constants', () => ({
  DEBUG: true
}));

// Mock package.json import
jest.mock('../../package.json', () => ({
  version: '1.0.0'
}));

describe('Extension', () => {
  const mockContext = {
    subscriptions: [],
    extensionPath: '/mock/extension/path',
    globalState: { get: jest.fn(), update: jest.fn() },
    workspaceState: { get: jest.fn(), update: jest.fn() }
  } as unknown as vscode.ExtensionContext;

  beforeEach(() => {
    jest.clearAllMocks();
    (configuration.configure as jest.Mock).mockReturnValue(undefined);
    (configuration.get as jest.Mock).mockReturnValue(false);
    (Core as jest.MockedClass<typeof Core>).mockImplementation(() => ({} as Core));
  });

  describe('activate', () => {
    it('should activate successfully', () => {
      activate(mockContext);
      
      expect(configuration.configure).toHaveBeenCalledWith(mockContext);
      expect(logger.logInfo).toHaveBeenCalledWith('Starting Keeper Security for VS Code.');
      expect(logger.logInfo).toHaveBeenCalledWith('Extension Version: 1.0.0.');
      expect(Core).toHaveBeenCalledWith(mockContext);
      expect(logger.logInfo).toHaveBeenCalledWith('Keeper Security extension activated successfully');
    });

    it('should enable debug logging when debug setting is true', () => {
      (configuration.get as jest.Mock).mockReturnValue(true);
      
      activate(mockContext);
      
      expect(logger.setOutputLevel).toHaveBeenCalledWith('DEBUG');
      expect(logger.logDebug).toHaveBeenCalledWith('Debug logging enabled');
    });
    
    it('should handle activation errors gracefully', () => {
      const error = new Error('Activation failed');
      (Core as jest.MockedClass<typeof Core>).mockImplementation(() => {
        throw error;
      });
      
      activate(mockContext);
      
      expect(logger.logError).toHaveBeenCalledWith('Failed to activate extension', error);
      expect(vscode.window.showErrorMessage).toHaveBeenCalledWith(
        'Keeper Security extension failed to activate: Activation failed'
      );
    });

    it('should handle unknown activation errors', () => {
      (Core as jest.MockedClass<typeof Core>).mockImplementation(() => {
        throw 'Unknown error';
      });
      
      activate(mockContext);
      
      expect(vscode.window.showErrorMessage).toHaveBeenCalledWith(
        'Keeper Security extension failed to activate: Unknown error'
      );
    });
  });

  describe('deactivate', () => {
    it('should log deactivation message', () => {
      deactivate();
      
      expect(logger.logInfo).toHaveBeenCalledWith('Keeper Security extension deactivated');
    });
  });
}); 