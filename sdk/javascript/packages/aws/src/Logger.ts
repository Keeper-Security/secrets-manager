import pino from 'pino';
import { LoggerLogLevelOptions } from './enum';

export function getLogger(logLevel: LoggerLogLevelOptions): pino.Logger {
  return pino({
    level: logLevel || process.env.LOG_LEVEL || LoggerLogLevelOptions.info,
    transport: {
      target: 'pino-pretty',
      options: { colorize: true },
    },
  });
}