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
exports.SettingsService = void 0;
const vscode = __importStar(require("vscode"));
class SettingsService {
    constructor(context) {
        this.context = context;
        this.setupConfigurationWatcher();
    }
    setupConfigurationWatcher() {
        // Listen for configuration changes
        vscode.workspace.onDidChangeConfiguration((event) => {
            if (event.affectsConfiguration(SettingsService.CONFIG_SECTION)) {
                this.onConfigurationChanged();
            }
        });
    }
    onConfigurationChanged() {
        // Notify other services that configuration has changed
        vscode.commands.executeCommand('keeper.configurationChanged');
    }
    // Public methods to open settings
    async openSettings() {
        await vscode.commands.executeCommand('workbench.action.openSettings', 'keeper');
    }
    async openKeeperSettings() {
        await vscode.commands.executeCommand('workbench.action.openSettings', '@ext:keeper-secrets-manager');
    }
    // Configuration getters
    getHostname() {
        return vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).get('hostname', 'keepersecurity.com');
    }
    getShowSecretValues() {
        return vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).get('showSecretValues', false);
    }
    getClipboardAutoClear() {
        return vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).get('clipboardAutoClear', true);
    }
    getTerminalDetection() {
        return vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).get('terminalDetection', true);
    }
    // Configuration setters
    async setHostname(hostname) {
        await vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).update('hostname', hostname, vscode.ConfigurationTarget.Global);
    }
    async setShowSecretValues(show) {
        await vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).update('showSecretValues', show, vscode.ConfigurationTarget.Global);
    }
    async setClipboardAutoClear(enabled) {
        await vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).update('clipboardAutoClear', enabled, vscode.ConfigurationTarget.Global);
    }
    async setTerminalDetection(enabled) {
        await vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).update('terminalDetection', enabled, vscode.ConfigurationTarget.Global);
    }
    // Authentication status updaters (for display in settings)
    async updateAuthenticationStatus(type, lastAuthenticated, secretCount) {
        const config = vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION);
        await Promise.all([
            config.update('authentication.type', type, vscode.ConfigurationTarget.Global),
            config.update('authentication.lastAuthenticated', lastAuthenticated ? lastAuthenticated.toLocaleString() : 'Never', vscode.ConfigurationTarget.Global),
            config.update('authentication.secretCount', secretCount, vscode.ConfigurationTarget.Global)
        ]);
    }
    async updateFavoritesCount(count) {
        await vscode.workspace.getConfiguration(SettingsService.CONFIG_SECTION).update('quickAccessFavorites', count, vscode.ConfigurationTarget.Global);
    }
    // Convenience method to toggle secret visibility
    async toggleSecretVisibility() {
        const current = this.getShowSecretValues();
        await this.setShowSecretValues(!current);
        const message = !current
            ? '👁️ Secret values are now visible'
            : '🙈 Secret values are now masked';
        vscode.window.showInformationMessage(message);
    }
    // Method to show a quick settings picker
    async showQuickSettings() {
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
        if (!selected)
            return;
        switch (selected.action) {
            case 'openSettings':
                await this.openSettings();
                break;
            case 'toggleVisibility':
                await this.toggleSecretVisibility();
                break;
            case 'toggleClipboard':
                await this.setClipboardAutoClear(!this.getClipboardAutoClear());
                vscode.window.showInformationMessage(this.getClipboardAutoClear()
                    ? 'Clipboard auto-clear enabled'
                    : 'Clipboard auto-clear disabled');
                break;
            case 'toggleTerminal':
                await this.setTerminalDetection(!this.getTerminalDetection());
                vscode.window.showInformationMessage(this.getTerminalDetection()
                    ? 'Terminal detection enabled'
                    : 'Terminal detection disabled');
                break;
            case 'logout':
                await vscode.commands.executeCommand('keeper.logout');
                break;
        }
    }
    // Method to reset authentication settings
    async resetAuthenticationSettings() {
        await this.updateAuthenticationStatus('none', null, 0);
    }
    // Method to get all current settings as an object
    getCurrentSettings() {
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
    dispose() {
        // Cleanup if needed
    }
}
exports.SettingsService = SettingsService;
SettingsService.CONFIG_SECTION = 'keeper';
//# sourceMappingURL=settingsService.js.map