/* eslint-disable @typescript-eslint/no-explicit-any */
// Enhanced VS Code API mock for comprehensive Jest testing

// Add Position and Range classes that parsers need
export class Position {
  constructor(public readonly line: number, public readonly character: number) {}
}

export class Range {
  constructor(
    public readonly start: Position,
    public readonly end: Position
  ) {}
}

export const window = {
  showInformationMessage: jest.fn().mockResolvedValue(undefined),
  showErrorMessage: jest.fn().mockResolvedValue(undefined),
  showWarningMessage: jest.fn().mockResolvedValue(undefined),
  showInputBox: jest.fn().mockResolvedValue(undefined),
  showQuickPick: jest.fn().mockResolvedValue(undefined),
  createOutputChannel: jest.fn(() => ({
    appendLine: jest.fn(),
    append: jest.fn(),
    show: jest.fn(),
    hide: jest.fn(),
    dispose: jest.fn(),
    clear: jest.fn()
  })),
  createStatusBarItem: jest.fn(() => ({
    text: '',
    tooltip: '',
    show: jest.fn(),
    hide: jest.fn(),
    dispose: jest.fn()
  })),
  activeTextEditor: undefined,
  visibleTextEditors: [],
  onDidChangeActiveTextEditor: jest.fn(),
  onDidChangeWindowState: jest.fn(),
  onDidChangeTextEditorSelection: jest.fn(),
  onDidChangeTextEditorVisibleRanges: jest.fn(),
  onDidChangeTextEditorOptions: jest.fn(),
  onDidChangeTextEditorViewColumn: jest.fn(),
  onDidCloseTerminal: jest.fn(),
  onDidOpenTerminal: jest.fn(),
  onDidChangeTerminalDimensions: jest.fn(),
  onDidChangeTerminalState: jest.fn(),
  onDidChangeActiveColorTheme: jest.fn(),
  onDidChangeFileIconTheme: jest.fn(),
  onDidChangeProductIconTheme: jest.fn(),
  onDidChangeWorkspaceFolders: jest.fn(),
  onDidChangeConfiguration: jest.fn(),
  onDidChangeTextDocument: jest.fn(),
  onDidCloseTextDocument: jest.fn(),
  onDidOpenTextDocument: jest.fn(),
  onDidSaveTextDocument: jest.fn(),
  onDidChangeVisibleTextEditors: jest.fn()
};

export const commands = {
  registerCommand: jest.fn(),
  executeCommand: jest.fn()
};

export const workspace = {
  getConfiguration: jest.fn(() => ({
    get: jest.fn(),
    update: jest.fn()
  })),
  onDidChangeConfiguration: jest.fn(),
  workspaceFolders: [],
  onDidChangeWorkspaceFolders: jest.fn()
};

export const ExtensionContext = jest.fn();
export const Uri = {
  file: jest.fn(),
  parse: jest.fn()
};

export const StatusBarAlignment = {
  Left: 1,
  Right: 2
};

export const TextDocument = {
  languageId: 'typescript',
  fileName: 'test.ts'
};

// Add EventEmitter mock
export class EventEmitter<T = any> {
  private listeners: Array<(value: T) => void> = [];
  
  fire(value: T): void {
    this.listeners.forEach(listener => listener(value));
  }
  
  get event(): (listener: (value: T) => void) => void {
    return (listener: (value: T) => void) => {
      this.listeners.push(listener);
    };
  }
  
  dispose(): void {
    this.listeners = [];
  }
}

export default {
  Position,
  Range,
  window,
  commands,
  workspace,
  ExtensionContext,
  Uri,
  StatusBarAlignment,
  TextDocument,
  EventEmitter
}; 