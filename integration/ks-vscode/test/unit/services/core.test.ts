import { Core } from '../../../src/services/core';
import { CliService } from '../../../src/services/cli';
import { CommandService } from '../../../src/commands';
import { StorageManager } from '../../../src/commands/storage/storageManager';
import { SecretDetectionService } from '../../../src/services/secretDetection';
import { StatusBarSpinner } from '../../../src/utils/helper';
import { logger } from '../../../src/utils/logger';
import * as vscode from 'vscode';

// Mock dependencies
jest.mock('../../../src/services/cli');
jest.mock('../../../src/commands');
jest.mock('../../../src/commands/storage/storageManager');
jest.mock('../../../src/services/secretDetection');
jest.mock('../../../src/utils/helper');
jest.mock('../../../src/utils/logger');

describe('Core', () => {
  let mockContext: vscode.ExtensionContext;
  let mockCliService: jest.Mocked<CliService>;
  let mockStorageManager: jest.Mocked<StorageManager>;
  let mockSpinner: jest.Mocked<StatusBarSpinner>;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockContext = {
      subscriptions: [],
      extensionPath: '/mock/extension/path',
      globalState: { get: jest.fn(), update: jest.fn() },
      workspaceState: { get: jest.fn(), update: jest.fn() }
    } as unknown as vscode.ExtensionContext;

    mockCliService = {
      dispose: jest.fn()
    } as unknown as jest.Mocked<CliService>;

    mockStorageManager = {} as unknown as jest.Mocked<StorageManager>;

    mockSpinner = {
      dispose: jest.fn()
    } as unknown as jest.Mocked<StatusBarSpinner>;

    (StatusBarSpinner as jest.MockedClass<typeof StatusBarSpinner>).mockImplementation(() => mockSpinner);
    (CliService as jest.MockedClass<typeof CliService>).mockImplementation(() => mockCliService);
    (StorageManager as jest.MockedClass<typeof StorageManager>).mockImplementation(() => mockStorageManager);
    (CommandService as jest.MockedClass<typeof CommandService>).mockImplementation(() => ({} as CommandService));
    (SecretDetectionService as jest.MockedClass<typeof SecretDetectionService>).mockImplementation(() => ({} as SecretDetectionService));
  });

  describe('constructor', () => {
    it('should initialize core service successfully', () => {
      new Core(mockContext);
      
      expect(StatusBarSpinner).toHaveBeenCalled();
      expect(CliService).toHaveBeenCalledWith(mockContext, mockSpinner);
      expect(StorageManager).toHaveBeenCalledWith(mockContext, mockCliService, mockSpinner);
      expect(CommandService).toHaveBeenCalledWith(mockContext, mockCliService, mockSpinner, mockStorageManager);
      expect(SecretDetectionService).toHaveBeenCalledWith(mockContext);
      expect(mockContext.subscriptions).toHaveLength(1);
      expect(logger.logDebug).toHaveBeenCalledWith('Initializing Core service');
      expect(logger.logDebug).toHaveBeenCalledWith('Core service initialization completed');
    });

    it('should register disposal handler', () => {
      new Core(mockContext);
      
      expect(mockContext.subscriptions).toHaveLength(1);
      const subscription = mockContext.subscriptions[0];
      expect(subscription.dispose).toBeDefined();
    });
  });

  describe('dispose', () => {
    it('should dispose resources when called', () => {
      new Core(mockContext);
      
      // Get the disposal handler
      const subscription = mockContext.subscriptions[0];
      subscription.dispose();
      
      expect(mockCliService.dispose).toHaveBeenCalled();
      expect(mockSpinner.dispose).toHaveBeenCalled();
      expect(logger.logDebug).toHaveBeenCalledWith('Disposing Core service resources');
      expect(logger.logDebug).toHaveBeenCalledWith('Core service disposal completed');
    });
  });
}); 