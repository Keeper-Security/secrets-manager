// Global Jest setup for VS Code extension tests
import { jest } from '@jest/globals';

jest.mock('vscode');

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Mock timers for interval-based tests
jest.useFakeTimers();

// Mock process methods with simpler typing
global.process = {
  ...process,
  exit: jest.fn(),
  on: jest.fn(),
  once: jest.fn(),
  emit: jest.fn(),
} as unknown as typeof process;

// Mock Buffer if not available
if (typeof Buffer === 'undefined') {
  global.Buffer = {
    from: jest.fn(),
    alloc: jest.fn(),
    allocUnsafe: jest.fn(),
    isBuffer: jest.fn(),
  } as unknown as typeof Buffer;
}

beforeEach(() => {
  jest.clearAllMocks();
  jest.clearAllTimers();
});

afterEach(() => {
  jest.useRealTimers();
});

// Global test timeout
jest.setTimeout(10000); 