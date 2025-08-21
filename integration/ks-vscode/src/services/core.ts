import { ExtensionContext } from 'vscode';
import { CliService } from './cli';
import { CommandService } from '../commands';
import { StatusBarSpinner } from '../utils/helper';
import { StorageManager } from '../commands/storage/storageManager';
import { SecretDetectionService } from './secretDetection';
import { logger } from '../utils/logger';

export class Core {
  private cliService!: CliService;
  private spinner: StatusBarSpinner;
  private storageManager!: StorageManager;

  public constructor(public context: ExtensionContext) {
    logger.logDebug('Initializing Core service');
    this.spinner = new StatusBarSpinner();
    this.initializeServices();

    // Register disposal handler
    this.context.subscriptions.push({
      dispose: () => this.dispose(),
    });
    logger.logDebug('Core service initialization completed');
  }

  private initializeServices(): void {
    logger.logDebug('Starting service initialization');

    this.cliService = new CliService(this.context, this.spinner);
    logger.logDebug('CLI service initialized');

    this.storageManager = new StorageManager(
      this.context,
      this.cliService,
      this.spinner
    );
    logger.logDebug('Storage manager initialized');

    new CommandService(
      this.context,
      this.cliService,
      this.spinner,
      this.storageManager
    );
    logger.logDebug('Command service initialized');

    new SecretDetectionService(this.context);
    logger.logDebug('Secret detection service initialized');

    logger.logDebug('All services initialized successfully');
  }

  private dispose(): void {
    logger.logDebug('Disposing Core service resources');
    // Clean up resources
    this.cliService.dispose();
    this.spinner.dispose();
    logger.logDebug('Core service disposal completed');
  }
}
