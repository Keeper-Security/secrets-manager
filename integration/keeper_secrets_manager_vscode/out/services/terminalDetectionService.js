"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TerminalDetectionService = void 0;
const vscode = __importStar(require("vscode"));
class TerminalDetectionService {
    constructor(quickAccessService, settingsService) {
        this.quickAccessService = quickAccessService;
        this.settingsService = settingsService;
        this.disposables = [];
        this.terminalProcessNotifications = new Map();
        this.setupTerminalListeners();
    }
    setupTerminalListeners() {
        // Listen for terminal creation
        this.disposables.push(vscode.window.onDidOpenTerminal((terminal) => {
            this.onTerminalOpened(terminal);
        }));
        // Listen for terminal close
        this.disposables.push(vscode.window.onDidCloseTerminal((terminal) => {
            this.onTerminalClosed(terminal);
        }));
        // Note: Terminal text monitoring is limited in VS Code API
        // We'll focus on terminal open/close events for now
    }
    onTerminalOpened(terminal) {
        // Show a subtle notification when terminal opens
        const terminalId = this.getTerminalId(terminal);
        // Clear any existing notification timeout
        const existingTimeout = this.terminalProcessNotifications.get(terminalId);
        if (existingTimeout) {
            clearTimeout(existingTimeout);
        }
        // Set a timeout to show quick access hint after 2 seconds
        const timeout = setTimeout(() => {
            this.showQuickAccessHint();
            this.detectCommonPrompts(terminal.name);
            this.terminalProcessNotifications.delete(terminalId);
        }, 2000);
        this.terminalProcessNotifications.set(terminalId, timeout);
    }
    onTerminalClosed(terminal) {
        const terminalId = this.getTerminalId(terminal);
        const timeout = this.terminalProcessNotifications.get(terminalId);
        if (timeout) {
            clearTimeout(timeout);
            this.terminalProcessNotifications.delete(terminalId);
        }
    }
    // Note: Terminal text monitoring is limited in VS Code API
    // This method would detect prompts if the API was available
    detectCommonPrompts(terminalName) {
        // For now, we'll just detect based on terminal name or common patterns
        // This is a simplified approach since we can't monitor terminal output directly
        if (terminalName.toLowerCase().includes('git') ||
            terminalName.toLowerCase().includes('ssh') ||
            terminalName.toLowerCase().includes('gpg')) {
            this.showSecretPromptDetected('Authentication may be required');
        }
    }
    showQuickAccessHint() {
        // Check if terminal detection is enabled in settings
        const terminalDetectionEnabled = this.settingsService?.getTerminalDetection() ?? true;
        if (!terminalDetectionEnabled) {
            return;
        }
        // Only show hint if user is authenticated
        const statusBarText = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
        statusBarText.text = '💡 Tip: Use Quick Secret Launcher for terminal auth';
        statusBarText.command = 'keeper.quickAccess';
        statusBarText.tooltip = 'Click to open Quick Secret Launcher';
        statusBarText.show();
        // Hide the hint after 8 seconds
        setTimeout(() => {
            statusBarText.dispose();
        }, 8000);
    }
    showSecretPromptDetected(data) {
        // Check if terminal detection is enabled in settings
        const terminalDetectionEnabled = this.settingsService?.getTerminalDetection() ?? true;
        if (!terminalDetectionEnabled) {
            return;
        }
        // Extract the type of prompt for better UX
        let promptType = 'credential';
        if (data.toLowerCase().includes('password')) {
            promptType = 'password';
        }
        else if (data.toLowerCase().includes('token')) {
            promptType = 'token';
        }
        else if (data.toLowerCase().includes('passphrase')) {
            promptType = 'passphrase';
        }
        else if (data.toLowerCase().includes('api')) {
            promptType = 'API key';
        }
        // Show notification with quick access
        vscode.window.showInformationMessage(`Terminal prompt detected: ${promptType}`, 'Quick Access Secrets', 'Dismiss').then(selection => {
            if (selection === 'Quick Access Secrets') {
                vscode.commands.executeCommand('keeper.quickAccess');
            }
        });
    }
    getTerminalId(terminal) {
        return `${terminal.name}-${terminal.processId || Math.random()}`;
    }
    dispose() {
        this.disposables.forEach(d => d.dispose());
        this.terminalProcessNotifications.forEach(timeout => clearTimeout(timeout));
        this.terminalProcessNotifications.clear();
    }
}
exports.TerminalDetectionService = TerminalDetectionService;
//# sourceMappingURL=terminalDetectionService.js.map