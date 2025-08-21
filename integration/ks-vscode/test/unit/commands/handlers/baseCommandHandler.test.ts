/* eslint-disable @typescript-eslint/no-explicit-any */
import { ExtensionContext } from 'vscode';
import { CliService } from '../../../../src/services/cli';
import { StatusBarSpinner } from '../../../../src/utils/helper';
import { BaseCommandHandler } from '../../../../src/commands/handlers/baseCommandHandler';
import { logger } from '../../../../src/utils/logger';

// Mock dependencies
jest.mock('../../../../src/services/cli');
jest.mock('../../../../src/utils/helper');
jest.mock('../../../../src/utils/logger');

describe('BaseCommandHandler', () => {
  let mockCliService: jest.Mocked<CliService>;
  let mockContext: ExtensionContext;
  let mockSpinner: jest.Mocked<StatusBarSpinner>;

  // Create a concrete implementation for testing
  class TestCommandHandler extends BaseCommandHandler {
    async execute(): Promise<void> {
      // Test implementation
    }
  }

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockCliService = {
      isCLIReady: jest.fn()
    } as unknown as jest.Mocked<CliService>;

    mockContext = {} as ExtensionContext;
    mockSpinner = {} as unknown as jest.Mocked<StatusBarSpinner>;
  });

  describe('constructor', () => {
    it('should initialize command handler with dependencies', () => {
      new TestCommandHandler(mockCliService, mockContext, mockSpinner);
      
      expect(logger.logDebug).toHaveBeenCalledWith('Initializing TestCommandHandler');
    });
  });

  describe('canExecute', () => {
    it('should return true when CLI is ready', async () => {
      mockCliService.isCLIReady.mockResolvedValue(true);
      
      const handler = new TestCommandHandler(mockCliService, mockContext, mockSpinner);
      const result = await (handler as any).canExecute();
      
      expect(result).toBe(true);
      expect(mockCliService.isCLIReady).toHaveBeenCalled();
      expect(logger.logDebug).toHaveBeenCalledWith('Checking if TestCommandHandler can execute');
      expect(logger.logDebug).toHaveBeenCalledWith('TestCommandHandler can execute: true');
    });

    it('should return false when CLI is not ready', async () => {
      mockCliService.isCLIReady.mockResolvedValue(false);
      
      const handler = new TestCommandHandler(mockCliService, mockContext, mockSpinner);
      const result = await (handler as any).canExecute();
      
      expect(result).toBe(false);
      expect(logger.logDebug).toHaveBeenCalledWith('TestCommandHandler can execute: false');
    });

    it('should handle CLI service errors', async () => {
      const error = new Error('CLI service error');
      mockCliService.isCLIReady.mockRejectedValue(error);
      
      const handler = new TestCommandHandler(mockCliService, mockContext, mockSpinner);
      
      await expect((handler as any).canExecute()).rejects.toThrow('CLI service error');
    });
  });

  describe('execute', () => {
    it('should be abstract and require implementation', () => {
      const handler = new TestCommandHandler(mockCliService, mockContext, mockSpinner);
      
      expect(handler.execute).toBeDefined();
      expect(typeof handler.execute).toBe('function');
    });
  });
}); 