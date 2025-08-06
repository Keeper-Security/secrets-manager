import * as vscode from 'vscode';
import { 
    getSecrets, 
    initializeStorage, 
    localConfigStorage, 
    inMemoryStorage,
    loadJsonConfig,
    SecretManagerOptions,
    KeeperRecord,
    KeeperSecrets
} from '@keeper-security/secrets-manager-core';
import { SettingsService } from './settingsService';
import { ConfigurationManager } from './configurationManager';

export interface KSMConfig {
    hostname: string;
    base64Config?: string;
    oneTimeToken?: string;
}

export class KSMService {
    private context: vscode.ExtensionContext;
    private configurationManager: ConfigurationManager;
    private settingsService: SettingsService | undefined;

    constructor(context: vscode.ExtensionContext, configurationManager: ConfigurationManager, settingsService?: SettingsService) {
        this.context = context;
        this.configurationManager = configurationManager;
        this.settingsService = settingsService;
    }

    public setSettingsService(settingsService: SettingsService): void {
        this.settingsService = settingsService;
    }

    async authenticate(): Promise<void> {
        // Legacy method for backward compatibility
        // This will delegate to the ConfigurationManager
        const activeConfig = this.configurationManager.getActiveConfiguration();
        if (!activeConfig) {
            vscode.window.showWarningMessage('No active configuration found. Please add a configuration in the KSM Devices panel.');
            return;
        }

        if (!activeConfig.isAuthenticated) {
            try {
                await this.configurationManager.authenticateConfiguration(activeConfig.id);
                vscode.window.showInformationMessage('Authenticated successfully!');
            } catch (error) {
                const errorMessage = this.parseAuthenticationError(error);
                vscode.window.showErrorMessage(`Authentication failed: ${errorMessage}`);
                throw error;
            }
        }
    }


    async refreshSecrets(): Promise<void> {
        const activeConfig = this.configurationManager.getActiveConfiguration();
        if (!activeConfig) {
            throw new Error('No active configuration');
        }
        
        await this.configurationManager.refreshConfiguration(activeConfig.id);
    }

    getSecrets(): KeeperRecord[] {
        const activeConfig = this.configurationManager.getActiveConfiguration();
        return activeConfig?.records || [];
    }

    isAuthenticated(): boolean {
        const activeConfig = this.configurationManager.getActiveConfiguration();
        return activeConfig?.isAuthenticated || false;
    }

    getRecordByUid(uid: string): KeeperRecord | undefined {
        const secrets = this.getSecrets();
        return secrets.find(r => r.recordUid === uid);
    }

    private parseAuthenticationError(error: any): string {
        if (!error) {
            return 'Unknown authentication error';
        }

        // Extract error message from different error formats
        let errorMessage = '';
        
        if (typeof error === 'string') {
            errorMessage = error;
        } else if (error.message) {
            errorMessage = error.message;
        } else {
            errorMessage = String(error);
        }

        // Try to parse JSON error messages from the API
        try {
            const jsonError = JSON.parse(errorMessage);
            if (jsonError.error || jsonError.message) {
                return jsonError.error || jsonError.message;
            }
        } catch (e) {
            // Not JSON, continue with string parsing
        }

        // Common error patterns and user-friendly messages
        const errorPatterns = [
            {
                pattern: /One Time Access Token has been used/i,
                message: 'One-Time Token has already been used. Please generate a new token.'
            },
            {
                pattern: /Invalid token/i,
                message: 'Invalid One-Time Token. Please check your token and try again.'
            },
            {
                pattern: /Token expired/i,
                message: 'One-Time Token has expired. Please generate a new token.'
            },
            {
                pattern: /Invalid base64/i,
                message: 'Invalid base64 configuration format. Please check your configuration.'
            },
            {
                pattern: /Invalid.*configuration/i,
                message: 'Invalid configuration format. Please check your base64 configuration or One-Time Token.'
            },
            {
                pattern: /Unauthorized/i,
                message: 'Authentication failed. Please check your credentials and try again.'
            },
            {
                pattern: /Network error|fetch failed|ENOTFOUND/i,
                message: 'Network error. Please check your internet connection and Keeper hostname.'
            },
            {
                pattern: /clientId.*not found/i,
                message: 'Client ID not found. Your configuration may be invalid or expired.'
            },
            {
                pattern: /Application.*not found/i,
                message: 'Application not found. Please check your Keeper application configuration.'
            },
            {
                pattern: /signature.*invalid/i,
                message: 'Invalid signature. Your configuration may be corrupted or tampered with.'
            },
            {
                pattern: /https:\/\/keepersecurity\.com\/api\/rest/i,
                message: 'API request failed. The token may be invalid, expired, or already used.'
            }
        ];

        // Check for known error patterns
        for (const { pattern, message } of errorPatterns) {
            if (pattern.test(errorMessage)) {
                return message;
            }
        }

        // If no pattern matches, return a cleaned up version of the original error
        const cleanError = errorMessage
            .replace(/^Error:\s*/i, '')
            .replace(/\{".*?\}/, 'API error')
            .replace(/https:\/\/[^\s]+/g, 'Keeper API')
            .substring(0, 200); // Limit length

        return cleanError || 'Authentication failed with unknown error';
    }

    async logout(): Promise<void> {
        const activeConfig = this.configurationManager.getActiveConfiguration();
        if (activeConfig) {
            await this.configurationManager.removeConfiguration(activeConfig.id);
            vscode.window.showInformationMessage('Logged out of Keeper Secrets Manager');
        }
    }

    getFolders(): any[] {
        const activeConfig = this.configurationManager.getActiveConfiguration();
        return activeConfig?.folders || [];
    }

    async createRecord(folderUid: string, recordData: any): Promise<string> {
        const activeConfig = this.configurationManager.getActiveConfiguration();
        if (!activeConfig) {
            throw new Error('No active configuration');
        }

        return await this.configurationManager.createRecord(activeConfig.id, folderUid, recordData);
    }

    async resolveNotation(notation: string): Promise<string> {
        const activeConfig = this.configurationManager.getActiveConfiguration();
        if (!activeConfig) {
            throw new Error('No active configuration');
        }

        return await this.configurationManager.resolveNotation(notation, activeConfig.id);
    }

    // Update authentication status in settings
    private async updateAuthenticationStatus(): Promise<void> {
        if (!this.settingsService) return;

        const activeConfig = this.configurationManager.getActiveConfiguration();
        const type = activeConfig?.isAuthenticated ? activeConfig.authType : 'none';
        const lastAuth = activeConfig?.lastAuth || null;
        const secretCount = activeConfig?.secretCount || 0;

        await this.settingsService.updateAuthenticationStatus(type, lastAuth, secretCount);
    }

    // Get authentication information for display
    public async getAuthenticationInfo(): Promise<any> {
        const activeConfig = this.configurationManager.getActiveConfiguration();
        
        return {
            type: activeConfig?.isAuthenticated ? activeConfig.authType : 'none',
            hostname: activeConfig?.hostname || 'keepersecurity.com',
            lastAuthenticated: activeConfig?.lastAuth?.getTime() || null,
            configPreview: activeConfig?.name || 'No configuration'
        };
    }

    // Method to check if secret values should be shown
    public shouldShowSecretValues(): boolean {
        return this.settingsService?.getShowSecretValues() || false;
    }
}