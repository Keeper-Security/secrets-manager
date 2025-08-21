import { ExtensionContext } from 'vscode';
import { CliService } from '../../services/cli';
import { StatusBarSpinner } from '../../utils/helper';
import { logger } from '../../utils/logger';

export interface ICommandHandler {
  execute(): Promise<void>;
}

export abstract class BaseCommandHandler implements ICommandHandler {
  constructor(
    protected cliService: CliService,
    protected context: ExtensionContext,
    protected spinner: StatusBarSpinner
  ) {
    logger.logDebug(`Initializing ${this.constructor.name}`);
  }

  abstract execute(): Promise<void>;

  protected async canExecute(): Promise<boolean> {
    logger.logDebug(`Checking if ${this.constructor.name} can execute`);
    const result = await this.cliService.isCLIReady();
    logger.logDebug(`${this.constructor.name} can execute: ${result}`);
    return result;
  }
}
