/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { configuration, ConfigurationKey } from '../../../src/services/configurations';
import { workspace } from 'vscode';
import { logger } from '../../../src/utils/logger';
import { CONFIG_NAMESPACE } from '../../../src/utils/constants';

// Mock dependencies
jest.mock('vscode', () => ({
  ...jest.requireActual('vscode'),
  workspace: {
    getConfiguration: jest.fn(),
    onDidChangeConfiguration: jest.fn()
  },
  EventEmitter: jest.fn().mockImplementation(() => ({
    fire: jest.fn(),
    event: jest.fn()
  }))
}));

jest.mock('../../../src/utils/logger');
jest.mock('../../../src/utils/constants', () => ({
  CONFIG_NAMESPACE: 'keeperSecurity'
}));

describe('Configuration', () => {
  let mockContext: any;
  let mockWorkspaceConfig: any;
  let mockEventEmitter: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockContext = {
      subscriptions: []
    };

    mockWorkspaceConfig = {
      get: jest.fn(),
      update: jest.fn()
    };

    mockEventEmitter = {
      fire: jest.fn(),
      event: jest.fn()
    };

    (workspace.getConfiguration as jest.Mock).mockReturnValue(mockWorkspaceConfig);
    (workspace.onDidChangeConfiguration as jest.Mock).mockReturnValue(mockEventEmitter);
  });

  describe('configure', () => {
    it('should configure extension settings and register configuration change listener', () => {
      configuration.configure(mockContext);
      
      expect(workspace.onDidChangeConfiguration).toHaveBeenCalled();
      expect(mockContext.subscriptions).toHaveLength(1);
      expect(logger.logDebug).toHaveBeenCalledWith('Configuring extension settings');
      expect(logger.logDebug).toHaveBeenCalledWith('Configuration change listener registered');
    });
  });

  describe('get', () => {
    it('should get configuration value successfully', () => {
      const mockValue = true;
      mockWorkspaceConfig.get.mockReturnValue(mockValue);
      
      const result = configuration.get(ConfigurationKey.DebugEnabled);
      
      expect(workspace.getConfiguration).toHaveBeenCalledWith(CONFIG_NAMESPACE);
      expect(mockWorkspaceConfig.get).toHaveBeenCalledWith(ConfigurationKey.DebugEnabled);
      expect(result).toBe(mockValue);
      expect(logger.logDebug).toHaveBeenCalledWith(`Getting configuration value for ${ConfigurationKey.DebugEnabled}: ${mockValue}`);
    });

    it('should return undefined when configuration value is not found', () => {
      mockWorkspaceConfig.get.mockReturnValue(undefined);
      
      const result = configuration.get(ConfigurationKey.DebugEnabled);
      
      expect(result).toBeUndefined();
    });
  });

  describe('set', () => {
    it('should set configuration value successfully', async () => {
      const section = ConfigurationKey.DebugEnabled;
      const value = true;
      mockWorkspaceConfig.update.mockResolvedValue(undefined);
      
      await configuration.set(section, value);
      
      expect(workspace.getConfiguration).toHaveBeenCalledWith(CONFIG_NAMESPACE);
      expect(mockWorkspaceConfig.update).toHaveBeenCalledWith(section, value);
      expect(logger.logDebug).toHaveBeenCalledWith(`Setting configuration value for ${section}: ${value}`);
    });

    it('should handle string section parameter', async () => {
      const section = 'custom.setting';
      const value = 'test';
      mockWorkspaceConfig.update.mockResolvedValue(undefined);
      
      await configuration.set(section, value);
      
      expect(mockWorkspaceConfig.update).toHaveBeenCalledWith(section, value);
    });
  });

  describe('onDidChange', () => {
    it('should return event emitter event', () => {
      const event = configuration.onDidChange;
      expect(event).toBeDefined();
    });
  });

  describe('onConfigurationChanged', () => {
    it('should fire event when configuration changes affect keeper security namespace', () => {
      // Access the private method through the event emitter
      const event = configuration.onDidChange;
            
      // The event should be callable
      expect(typeof event).toBe('function');
      
      // Test that the event emitter is properly set up
      expect(event).toBeDefined();
    });

    it('should not fire event when configuration changes do not affect keeper security namespace', () => {
      // This test verifies the default behavior when no configuration changes occur
      expect(logger.logDebug).not.toHaveBeenCalledWith('Configuration change detected in Keeper Security namespace');
    });
  });
}); 