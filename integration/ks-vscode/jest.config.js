module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/test/unit', '<rootDir>/src'],
  testMatch: [
    '**/__tests__/**/*.ts',
    '**/?(*.)+(spec|test).ts',
  ],
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/out/',
    '.*\\.integration\\.test\\.ts$',
    'test/unit/commands/index.test.ts',
  ],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: 'tsconfig.test.json'
    }]
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!test/**/*.ts',
    '!**/*.test.ts',
    '!**/*.spec.ts',
    '!src/commands/index.ts',
    '!src/providers/secretDetectionCodeLensProvider.ts'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  testTimeout: 10000,
  setupFilesAfterEnv: ['<rootDir>/test/unit/jest.setup.ts'],
  moduleNameMapper: {
    '^vscode$': '<rootDir>/test/__mocks__/vscode.ts'
  },
  clearMocks: true,
  restoreMocks: true,
  verbose: true
}; 