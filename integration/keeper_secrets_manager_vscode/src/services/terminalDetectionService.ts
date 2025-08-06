import * as vscode from 'vscode';
import { QuickAccessService } from './quickAccessService';
import { SettingsService } from './settingsService';

export class TerminalDetectionService {
    private disposables: vscode.Disposable[] = [];
    private terminalProcessNotifications: Map<string, NodeJS.Timeout> = new Map();

    constructor(
        private quickAccessService: QuickAccessService,
        private settingsService?: SettingsService
    ) {
        this.setupTerminalListeners();
    }

    private setupTerminalListeners(): void {
        // Listen for terminal creation
        this.disposables.push(
            vscode.window.onDidOpenTerminal((terminal) => {
                this.onTerminalOpened(terminal);
            })
        );

        // Listen for terminal close
        this.disposables.push(
            vscode.window.onDidCloseTerminal((terminal) => {
                this.onTerminalClosed(terminal);
            })
        );

        // Note: Terminal text monitoring is limited in VS Code API
        // We'll focus on terminal open/close events for now
    }

    private onTerminalOpened(terminal: vscode.Terminal): void {
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

    private onTerminalClosed(terminal: vscode.Terminal): void {
        const terminalId = this.getTerminalId(terminal);
        const timeout = this.terminalProcessNotifications.get(terminalId);
        if (timeout) {
            clearTimeout(timeout);
            this.terminalProcessNotifications.delete(terminalId);
        }
    }

    // Note: Terminal text monitoring is limited in VS Code API
    // This method would detect prompts if the API was available
    private detectCommonPrompts(terminalName: string): void {
        // For now, we'll just detect based on terminal name or common patterns
        // This is a simplified approach since we can't monitor terminal output directly
        
        if (terminalName.toLowerCase().includes('git') || 
            terminalName.toLowerCase().includes('ssh') ||
            terminalName.toLowerCase().includes('gpg')) {
            this.showSecretPromptDetected('Authentication may be required');
        }
    }

    private showQuickAccessHint(): void {
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

    private showSecretPromptDetected(data: string): void {
        // Check if terminal detection is enabled in settings
        const terminalDetectionEnabled = this.settingsService?.getTerminalDetection() ?? true;
        if (!terminalDetectionEnabled) {
            return;
        }

        // Extract the type of prompt for better UX
        let promptType = 'credential';
        if (data.toLowerCase().includes('password')) {
            promptType = 'password';
        } else if (data.toLowerCase().includes('token')) {
            promptType = 'token';
        } else if (data.toLowerCase().includes('passphrase')) {
            promptType = 'passphrase';
        } else if (data.toLowerCase().includes('api')) {
            promptType = 'API key';
        }

        // Show notification with quick access
        vscode.window.showInformationMessage(
            `Terminal prompt detected: ${promptType}`,
            'Quick Access Secrets',
            'Dismiss'
        ).then(selection => {
            if (selection === 'Quick Access Secrets') {
                vscode.commands.executeCommand('keeper.quickAccess');
            }
        });
    }

    private getTerminalId(terminal: vscode.Terminal): string {
        return `${terminal.name}-${terminal.processId || Math.random()}`;
    }

    public dispose(): void {
        this.disposables.forEach(d => d.dispose());
        this.terminalProcessNotifications.forEach(timeout => clearTimeout(timeout));
        this.terminalProcessNotifications.clear();
    }
}