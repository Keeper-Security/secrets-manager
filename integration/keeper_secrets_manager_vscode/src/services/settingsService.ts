import * as vscode from 'vscode';

export class SettingsService {
    private static readonly CONFIG_SECTION = 'keeper';

    constructor(private context: vscode.ExtensionContext) {
        this.setupConfigurationWatcher();
    }

    private setupConfigurationWatcher(): void {
        // Listen for configuration changes
        vscode.workspace.onDidChangeConfiguration((event) => {
            if (event.affectsConfiguration(SettingsService.CONFIG_SECTION)) {
                this.onConfigurationChanged();
            }
        });
    }

    private onConfigurationChanged(): void {
        // Notify other services that configuration has changed
        vscode.commands.executeCommand('keeper.configurationChanged');
    }

    // Public methods to open settings
    public async openSettings(): Promise<void> {
        await vscode.commands.executeCommand('workbench.action.openSettings', 'keeper');
    }

    public async openKeeperSettings(): Promise<void> {
        await vscode.commands.executeCommand('workbench.action.openSettings', '@ext:keeper-secrets-manager');
    }

    // Configuration getters
    public getHostname(): string {
        return vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).get<string>('hostname', 'keepersecurity.com');
    }

    public getShowSecretValues(): boolean {
        return vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).get<boolean>('showSecretValues', false);
    }

    public getClipboardAutoClear(): boolean {
        return vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).get<boolean>('clipboardAutoClear', true);
    }

    public getTerminalDetection(): boolean {
        return vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).get<boolean>('terminalDetection', true);
    }

    // Configuration setters
    public async setHostname(hostname: string): Promise<void> {
        await vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).update('hostname', hostname, vscode.ConfigurationTarget.Global);
    }

    public async setShowSecretValues(show: boolean): Promise<void> {
        await vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).update('showSecretValues', show, vscode.ConfigurationTarget.Global);
    }

    public async setClipboardAutoClear(enabled: boolean): Promise<void> {
        await vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).update('clipboardAutoClear', enabled, vscode.ConfigurationTarget.Global);
    }

    public async setTerminalDetection(enabled: boolean): Promise<void> {
        await vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).update('terminalDetection', enabled, vscode.ConfigurationTarget.Global);
    }

    // Authentication status updaters (for display in settings)
    public async updateAuthenticationStatus(type: string, lastAuthenticated: Date | null, secretCount: number): Promise<void> {
        const config = vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION);
        
        await Promise.all([
            config.update('authentication.type', type, vscode.ConfigurationTarget.Global),
            config.update('authentication.lastAuthenticated', 
                lastAuthenticated ? lastAuthenticated.toLocaleString() : 'Never', 
                vscode.ConfigurationTarget.Global),
            config.update('authentication.secretCount', secretCount, vscode.ConfigurationTarget.Global)
        ]);
    }

    public async updateFavoritesCount(count: number): Promise<void> {
        await vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).update(
            'quickAccessFavorites', 
            count, 
            vscode.ConfigurationTarget.Global
        );
    }

    // Convenience method to toggle secret visibility
    public async toggleSecretVisibility(): Promise<void> {
        const current = this.getShowSecretValues();
        await this.setShowSecretValues(!current);
        
        const message = !current 
            ? '👁️ Secret values are now visible' 
            : '🙈 Secret values are now masked';
        
        vscode.window.showInformationMessage(message);
    }

    // Method to show a quick settings picker
    public async showQuickSettings(): Promise<void> {
        const items = [
            {
                label: '$(gear) Open Keeper Settings',
                description: 'Open the full settings page',
                action: 'openSettings'
            },
            {
                label: this.getShowSecretValues() ? '$(eye-closed) Hide Secret Values' : '$(eye) Show Secret Values',
                description: 'Toggle secret value visibility',
                action: 'toggleVisibility'
            },
            {
                label: this.getClipboardAutoClear() ? '$(check) Auto-clear clipboard (enabled)' : '$(x) Auto-clear clipboard (disabled)',
                description: 'Toggle automatic clipboard clearing',
                action: 'toggleClipboard'
            },
            {
                label: this.getTerminalDetection() ? '$(check) Terminal detection (enabled)' : '$(x) Terminal detection (disabled)',
                description: 'Toggle terminal authentication hints',
                action: 'toggleTerminal'
            },
            {
                label: '$(sign-out) Logout',
                description: 'Clear authentication and logout',
                action: 'logout'
            }
        ];

        const selected = await vscode.window.showQuickPick(items, {
            placeHolder: 'Keeper Settings - Choose an option'
        });

        if (!selected) return;

        switch (selected.action) {
            case 'openSettings':
                await this.openSettings();
                break;
            case 'toggleVisibility':
                await this.toggleSecretVisibility();
                break;
            case 'toggleClipboard':
                await this.setClipboardAutoClear(!this.getClipboardAutoClear());
                vscode.window.showInformationMessage(
                    this.getClipboardAutoClear() 
                        ? 'Clipboard auto-clear enabled' 
                        : 'Clipboard auto-clear disabled'
                );
                break;
            case 'toggleTerminal':
                await this.setTerminalDetection(!this.getTerminalDetection());
                vscode.window.showInformationMessage(
                    this.getTerminalDetection() 
                        ? 'Terminal detection enabled' 
                        : 'Terminal detection disabled'
                );
                break;
            case 'logout':
                await vscode.commands.executeCommand('keeper.logout');
                break;
        }
    }

    // Method to reset authentication settings
    public async resetAuthenticationSettings(): Promise<void> {
        await this.updateAuthenticationStatus('none', null, 0);
    }

    // Method to get all current settings as an object
    public getCurrentSettings(): any {
        const config = vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION);
        return {
            hostname: this.getHostname(),
            showSecretValues: this.getShowSecretValues(),
            clipboardAutoClear: this.getClipboardAutoClear(),
            terminalDetection: this.getTerminalDetection(),
            authentication: {
                type: config.get('authentication.type'),
                lastAuthenticated: config.get('authentication.lastAuthenticated'),
                secretCount: config.get('authentication.secretCount')
            },
            quickAccessFavorites: config.get('quickAccessFavorites')
        };
    }

    public dispose(): void {
        // Cleanup if needed
    }
}