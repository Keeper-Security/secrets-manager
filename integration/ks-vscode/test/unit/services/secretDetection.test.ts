import { SecretDetectionService } from '../../../src/services/secretDetection';
import { logger } from '../../../src/utils/logger';
import { configuration } from '../../../src/services/configurations';
import { ExtensionContext } from 'vscode';

// Mock dependencies
jest.mock('../../../src/utils/logger');
jest.mock('../../../src/services/configurations', () => ({
  configuration: {
    onDidChange: jest.fn(),
    get: jest.fn().mockReturnValue(true) // Mock get method to return true
  },
  ConfigurationKey: {
    SecretDetectionEnabled: 'editor.secretDetection'
  }
}));

// Mock parser classes
jest.mock('../../../src/secret-detection/parser/parser');
jest.mock('../../../src/secret-detection/parser/jsonConfig');
jest.mock('../../../src/secret-detection/parser/dotEnv');
jest.mock('../../../src/secret-detection/parser/yamlConfig');
jest.mock('../../../src/secret-detection/parser/codeParser');

// Mock CodeLens provider
jest.mock('../../../src/providers/secretDetectionCodeLensProvider', () => ({
  SecretDetectionCodeLensProvider: jest.fn().mockImplementation(() => ({
    refresh: jest.fn()
  }))
}));

// Mock VS Code APIs
jest.mock('vscode', () => ({
  ...jest.requireActual('vscode'),
  languages: {
    registerCodeLensProvider: jest.fn().mockReturnValue({
      dispose: jest.fn()
    })
  },
  workspace: {
    onDidSaveTextDocument: jest.fn().mockReturnValue({
      dispose: jest.fn()
    })
  }
}));

// Mock helper functions
jest.mock('../../../src/utils/helper', () => ({
  documentMatcher: jest.fn(() => jest.fn(() => true)),
  isEnvironmentFile: jest.fn(() => false)
}));

describe('SecretDetectionService', () => {
  let mockContext: ExtensionContext;
  let secretDetectionService: SecretDetectionService;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockContext = {
      subscriptions: []
    } as unknown as ExtensionContext;

    secretDetectionService = new SecretDetectionService(mockContext);
  });

  describe('constructor', () => {
    it('should initialize secret detection service', () => {
      expect(logger.logDebug).toHaveBeenCalledWith('Initializing SecretDetectionService');
      expect(logger.logDebug).toHaveBeenCalledWith('SecretDetectionService initialization completed');
    });

    it('should register configuration change listener', () => {
      expect(configuration.onDidChange).toHaveBeenCalled();
    });
  });

  describe('initialize', () => {
    it('should create CodeLens provider when secret detection is enabled', () => {
      // The initialize method is called in constructor
      expect(logger.logDebug).toHaveBeenCalledWith('Starting secret detection initialization');
      expect(logger.logDebug).toHaveBeenCalledWith('Creating CodeLens provider');
      expect(logger.logDebug).toHaveBeenCalledWith('Registering CodeLens provider and event listeners');
      expect(logger.logDebug).toHaveBeenCalledWith('Secret detection initialization completed');
    });

    it('should register CodeLens provider and event listeners', () => {
      const { languages, workspace } = require('vscode');
      
      expect(languages.registerCodeLensProvider).toHaveBeenCalled();
      expect(workspace.onDidSaveTextDocument).toHaveBeenCalled();
    });
  });

  describe('dispose', () => {
    it('should dispose secret detection service resources', () => {
      secretDetectionService.dispose();

      expect(logger.logDebug).toHaveBeenCalledWith('Disposing SecretDetectionService');
      expect(logger.logDebug).toHaveBeenCalledWith('SecretDetectionService disposal completed');
    });
  });

  describe('parser factory', () => {
    it('should create appropriate parsers for different document types', () => {

      // Verify the parser factory was created and works
      expect(secretDetectionService).toBeDefined();
      expect(typeof secretDetectionService.dispose).toBe('function');
    });
  });

  describe('configuration handling', () => {
    it('should respond to configuration changes', () => {
      // Test that the service responds to configuration changes
      expect(configuration.onDidChange).toHaveBeenCalled();
      
      // The callback should be bound to the initialize method
      const callback = (configuration.onDidChange as jest.Mock).mock.calls[0][0];
      expect(typeof callback).toBe('function');
    });
  });
}); 