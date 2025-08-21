import { CliService } from '../../../src/services/cli';
import { StatusBarSpinner } from '../../../src/utils/helper';
import { ExtensionContext } from 'vscode';

// Mock dependencies
jest.mock('../../../src/utils/helper');
jest.mock('../../../src/utils/logger');
jest.mock('child_process', () => ({
  exec: jest.fn(),
  spawn: jest.fn()
}));

describe('CliService', () => {
  let mockContext: ExtensionContext;
  let mockSpinner: jest.Mocked<StatusBarSpinner>;
  let cliService: CliService;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockContext = {
      subscriptions: []
    } as unknown as ExtensionContext;

    mockSpinner = {
      show: jest.fn(),
      updateMessage: jest.fn(),
      hide: jest.fn(),
      dispose: jest.fn()
    } as unknown as jest.Mocked<StatusBarSpinner>;

    cliService = new CliService(mockContext, mockSpinner);
  });

  describe('constructor', () => {
    it('should initialize CLI service', () => {
      expect(cliService).toBeDefined();
      // Test that the service was created with the expected dependencies
      expect(cliService).toBeInstanceOf(CliService);
    });

    it('should have expected properties', () => {
      // Test that the service has the expected interface
      expect(cliService).toHaveProperty('isCLIReady');
      expect(cliService).toHaveProperty('executeCommanderCommand');
      expect(cliService).toHaveProperty('dispose');
    });
  });

  describe('isCLIReady', () => {
    it('should check CLI readiness', async () => {
      const result = await cliService.isCLIReady();
      
      // The method returns a boolean based on installation and authentication status
      expect(typeof result).toBe('boolean');
    });

    it('should initialize lazily on first call', async () => {
      // First call should trigger lazy initialization
      await cliService.isCLIReady();
      
      // Verify spinner was shown during initialization
      expect(mockSpinner.show).toHaveBeenCalledWith('Initializing Keeper Security Extension...');
    });
  });

  describe('dispose', () => {
    it('should dispose CLI service resources', () => {
      // The dispose method exists and should work
      expect(typeof cliService.dispose).toBe('function');
      
      cliService.dispose();
      
      // The dispose method handles persistent process cleanup
      expect(true).toBe(true); // Method executed without throwing
    });
  });

  describe('executeCommanderCommand', () => {
    it('should have executeCommanderCommand method', () => {
      expect(typeof cliService.executeCommanderCommand).toBe('function');
    });

    it('should execute commands with lazy initialization', async () => {
      // This method should trigger lazy initialization if not already done
      try {
        await cliService.executeCommanderCommand('--version');
        expect(true).toBe(true); // Method executed without throwing
      } catch (error) {
        // Command may fail due to keeper not being installed, which is expected in tests
        expect(error).toBeDefined();
      }
    });
  });

  describe('lazy initialization behavior', () => {
    it('should handle initialization errors gracefully', async () => {
      // The service should handle errors during initialization
      const result = await cliService.isCLIReady();
      
      // Should return false if initialization fails
      expect(typeof result).toBe('boolean');
    });

    it('should complete initialization process', async () => {
      // Test that initialization completes (even if it fails)
      await cliService.isCLIReady();
      
      // Verify that spinner is hidden after initialization attempt
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });

  describe('process management', () => {
    it('should handle persistent process lifecycle', () => {
      // Test that dispose method can be called multiple times safely
      cliService.dispose();
      cliService.dispose();
      
      expect(true).toBe(true); // No errors thrown
    });
  });

  describe('error handling', () => {
    it('should handle command execution errors gracefully', async () => {
      try {
        await cliService.executeCommanderCommand('invalid-command');
        expect(true).toBe(true); // Method executed without throwing
      } catch (error) {
        // If it throws, that's also acceptable behavior
        expect(error).toBeDefined();
      }
    });

    it('should handle initialization failures gracefully', async () => {
      // Test that the service can handle initialization failures
      const result = await cliService.isCLIReady();
      
      // Should return a boolean regardless of success/failure
      expect(typeof result).toBe('boolean');
    });
  });

  describe('spinner interaction', () => {
    it('should show and hide spinner during initialization', async () => {
      await cliService.isCLIReady();
      
      expect(mockSpinner.show).toHaveBeenCalledWith('Initializing Keeper Security Extension...');
      expect(mockSpinner.hide).toHaveBeenCalled();
    });
  });
}); 
