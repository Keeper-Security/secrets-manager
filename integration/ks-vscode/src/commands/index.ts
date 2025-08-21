/* eslint-disable @typescript-eslint/no-explicit-any */
import { commands, ExtensionContext } from 'vscode';
import { COMMANDS } from '../utils/constants';
import { CliService } from '../services/cli';
import { StatusBarSpinner } from '../utils/helper';
import { logger } from '../utils/logger';
import { ICommandHandler } from './handlers/baseCommandHandler';
import { SaveValueHandler } from './handlers/saveValueHandler';
import { GetValueHandler } from './handlers/getValueHandler';
import { GeneratePasswordHandler } from './handlers/generatePasswordHandler';
import { RunSecurelyHandler } from './handlers/runSecurelyHandler';
import { ChooseFolderHandler } from './handlers/chooseFolderHandler';
import { OpenLogsHandler } from './handlers/openLogsHandler';
import { StorageManager } from './storage/storageManager';

export class CommandService {
  private handlers!: Map<string, ICommandHandler>;
  private storageManager: StorageManager;

  constructor(
    private context: ExtensionContext,
    cliService: CliService,
    private spinner: StatusBarSpinner,
    storageManager: StorageManager
  ) {
    logger.logDebug('Initializing CommandService');
    this.storageManager = storageManager;
    this.initializeHandlers(cliService);
    this.registerCommands();
    logger.logDebug('CommandService initialization completed');
  }

  private initializeHandlers(cliService: CliService): void {
    logger.logDebug('Initializing command handlers');
    this.handlers = new Map([
      [
        COMMANDS.SAVE_VALUE_TO_VAULT,
        new SaveValueHandler(
          cliService,
          this.context,
          this.spinner,
          this.storageManager
        ),
      ],
      [
        COMMANDS.GET_VALUE_FROM_VAULT,
        new GetValueHandler(cliService, this.context, this.spinner),
      ],
      [
        COMMANDS.GENERATE_PASSWORD,
        new GeneratePasswordHandler(
          cliService,
          this.context,
          this.spinner,
          this.storageManager
        ),
      ],
      [
        COMMANDS.RUN_SECURELY,
        new RunSecurelyHandler(cliService, this.context, this.spinner),
      ],
      [
        COMMANDS.CHOOSE_FOLDER,
        new ChooseFolderHandler(
          cliService,
          this.context,
          this.spinner,
          this.storageManager
        ),
      ],
      [COMMANDS.OPEN_LOGS, new OpenLogsHandler()],
    ]);
    logger.logDebug(`Initialized ${this.handlers.size} command handlers`);
  }

  private registerCommands(): void {
    logger.logDebug('Registering Keeper Security VSCode commands');
    this.handlers.forEach((handler, command) => {
      logger.logDebug(`Registering command: ${command}`);
      this.context.subscriptions.push(
        commands.registerCommand(command, (...args: any[]) =>
          (handler as any).execute(...args)
        )
      );
    });
    logger.logDebug('All commands registered successfully');
  }
}
