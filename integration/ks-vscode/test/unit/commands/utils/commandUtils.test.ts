import { CommandUtils } from '../../../../src/commands/utils/commandUtils';
import { window } from 'vscode';

// Mock VSCode
jest.mock('vscode', () => ({
  window: {
    showInputBox: jest.fn(),
    showQuickPick: jest.fn(),
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

describe('Command Utils', () => {
  let mockWindow: jest.Mocked<typeof window>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockWindow = window as jest.Mocked<typeof window>;
  });

  describe('getSecretNameFromUser', () => {
    it('should get secret name from user successfully', async () => {
      mockWindow.showInputBox.mockResolvedValue('test-secret');
      
      const result = await CommandUtils.getSecretNameFromUser();
      
      expect(result).toBe('test-secret');
      expect(mockWindow.showInputBox).toHaveBeenCalledWith({
        ignoreFocusOut: true,
        prompt: 'What do you want to call this record?',
        placeHolder: 'Enter a name for this record. e.g. \'My Password\''
      });
    });

    it('should throw error when user cancels input', async () => {
      mockWindow.showInputBox.mockResolvedValue(undefined);
      
      await expect(CommandUtils.getSecretNameFromUser()).rejects.toThrow('No record name provided.');
    });

    it('should throw error when user provides empty input', async () => {
      mockWindow.showInputBox.mockResolvedValue('');
      
      await expect(CommandUtils.getSecretNameFromUser()).rejects.toThrow('No record name provided.');
    });
  });

  describe('getSecretFieldNameFromUser', () => {
    it('should get field name from user successfully', async () => {
      mockWindow.showInputBox.mockResolvedValue('password');
      
      const result = await CommandUtils.getSecretFieldNameFromUser();
      
      expect(result).toBe('password');
      expect(mockWindow.showInputBox).toHaveBeenCalledWith({
        ignoreFocusOut: true,
        prompt: 'What do you want to call this record field?',
        placeHolder: 'Enter a name for field. e.g. \'password\''
      });
    });

    it('should throw error when user cancels input', async () => {
      mockWindow.showInputBox.mockResolvedValue(undefined);
      
      await expect(CommandUtils.getSecretFieldNameFromUser()).rejects.toThrow('No record field name provided.');
    });

    it('should throw error when user provides empty input', async () => {
      mockWindow.showInputBox.mockResolvedValue('');
      
      await expect(CommandUtils.getSecretFieldNameFromUser()).rejects.toThrow('No record field name provided.');
    });
  });
}); 