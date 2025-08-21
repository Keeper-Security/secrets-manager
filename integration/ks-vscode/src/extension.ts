import pckg from '../package.json';
import { configuration, ConfigurationKey, Core } from './services';
import { logger } from './utils/logger';
import { ExtensionContext, window } from 'vscode';

export function activate(context: ExtensionContext): void {
  try {
    // Configure first
    configuration.configure(context);

    logger.logInfo(`Starting Keeper Security for VS Code.`);
    logger.logInfo(`Extension Version: ${pckg.version}.`);

    // Set debug mode if debug setting is enabled or debug constant is enabled
    const debugSetting = configuration.get<boolean>(
      ConfigurationKey.DebugEnabled
    );

    if (debugSetting) {
      logger.setOutputLevel('DEBUG');
      logger.logDebug('Debug logging enabled');
    }

    // Initialize core with all services
    new Core(context);

    logger.logInfo('Keeper Security extension activated successfully');
  } catch (error) {
    logger.logError('Failed to activate extension', error);
    window.showErrorMessage(
      `Keeper Security extension failed to activate: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

export function deactivate(): void {
  logger.logInfo('Keeper Security extension deactivated');
}
