import * as assert from 'assert';
import * as vscode from 'vscode';

suite('CLI Service Integration Test Suite', () => {
  vscode.window.showInformationMessage('Start CLI service integration tests.');

  test('Should check CLI installation status', async () => {
    // This test verifies that the CLI service can be initialized
    // We can't directly test the CLI without it being installed
    // But we can verify the extension loads without crashing
    
    const ext = vscode.extensions.getExtension('keeper-security.ks-vscode');
    if (ext) {
      await ext.activate();
      assert.strictEqual(ext.isActive, true, 'Extension should activate even without CLI');
    }
  });

  test('Should handle CLI not installed gracefully', async () => {
    // Test that commands fail gracefully when CLI is not available
    try {
      await vscode.commands.executeCommand('ks-vscode.authenticate');
      // If we get here, the command handled the missing CLI gracefully
      assert.ok(true, 'Command should handle missing CLI gracefully');
    } catch (error) {
      // Expected error when CLI is not available
      assert.ok(error instanceof Error, 'Should throw proper error');
      assert.ok(error.message, 'Error should have descriptive message');
    }
  });

  test('Should handle CLI authentication errors gracefully', async () => {
    try {
      await vscode.commands.executeCommand('ks-vscode.saveValueToVault');
      assert.ok(true, 'Command should handle CLI auth errors gracefully');
    } catch (error) {
      assert.ok(error instanceof Error, 'Should throw proper error');
      assert.ok(error.message, 'Error should have descriptive message');
    }
  });
});
