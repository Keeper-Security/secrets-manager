import { OpenLogsHandler } from '../../../../src/commands/handlers/openLogsHandler';
import { logger } from '../../../../src/utils/logger';

// Mock dependencies
jest.mock('../../../../src/utils/logger');

describe('OpenLogsHandler', () => {
  let openLogsHandler: OpenLogsHandler;

  beforeEach(() => {
    jest.clearAllMocks();
    openLogsHandler = new OpenLogsHandler();
  });

  describe('execute', () => {
    it('should open logs successfully', async () => {
      await openLogsHandler.execute();

      expect(logger.show).toHaveBeenCalled();
    });

    it('should handle errors when opening logs', async () => {
      const error = new Error('Failed to open logs');
      (logger.show as jest.Mock).mockRejectedValue(error);

      await expect(openLogsHandler.execute()).rejects.toThrow('Failed to open logs');
    });
  });

  describe('constructor', () => {
    it('should properly initialize', () => {
      expect(openLogsHandler).toBeInstanceOf(OpenLogsHandler);
    });
  });
}); 