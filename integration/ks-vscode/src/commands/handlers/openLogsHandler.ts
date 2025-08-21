import { logger } from '../../utils/logger';
import { ICommandHandler } from './baseCommandHandler';

export class OpenLogsHandler implements ICommandHandler {
  async execute(): Promise<void> {
    await logger.show();
  }
}
