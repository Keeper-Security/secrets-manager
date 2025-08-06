import * as vscode from 'vscode';
import { 
    getSecrets, 
    initializeStorage, 
    inMemoryStorage,
    SecretManagerOptions,
    KeeperRecord,
    KeeperSecrets
} from '@keeper-security/secrets-manager-core';
import { v4 as uuidv4 } from 'uuid';

export interface KSMConfiguration {
    id: string;                    // unique identifier (uuid)
    name: string;                  // KSM app name or user-provided name
    displayName: string;           // formatted display name (e.g., "Production (US)")
    hostname: string;              // keeper region
    authType: 'oneTimeToken' | 'base64Config';
    lastAuth?: Date;               // last authentication time
    secretCount?: number;          // cached secret count
    isAuthenticated: boolean;      // current authentication state
    folders?: KSMFolder[];         // cached folder structure
    records?: KeeperRecord[];      // cached secrets
}

export interface KSMFolder {
    uid: string;
    name: string;
    type: 'shared' | 'regular';    // Shared Folder (SF) vs Regular Folder (RF)
    parentUid?: string;            // for nested folders
    records: KSMRecord[];          // secrets in this folder
    subfolders: KSMFolder[];       // nested folders
}

export interface KSMRecord {
    uid: string;
    title: string;
    folderUid: string;
    fields: KSMField[];
    type: string;                  // record type
    recordUid: string;             // for compatibility with KeeperRecord
    data: {                        // for compatibility with KeeperRecord
        title: string;
        type: string;
        fields: any[];
    };
}

export interface KSMField {
    type: string;
    label: string;
    value: string[];
}

export interface StoredConfigurations {
    activeConfigId?: string;       // currently selected config
    configurations: KSMConfiguration[];
}

export class ConfigurationManager {
    private context: vscode.ExtensionContext;
    private configurations: Map<string, KSMConfiguration> = new Map();
    private activeConfigId?: string;
    private storageMap: Map<string, any> = new Map();
    private _onDidChangeConfigurations = new vscode.EventEmitter<KSMConfiguration[]>();
    private _onDidChangeActiveConfiguration = new vscode.EventEmitter<KSMConfiguration | undefined>();

    readonly onDidChangeConfigurations = this._onDidChangeConfigurations.event;
    readonly onDidChangeActiveConfiguration = this._onDidChangeActiveConfiguration.event;

    private readonly STORAGE_KEYS = {
        CONFIGURATIONS: 'keeper.configurations',
        ACTIVE_CONFIG: 'keeper.activeConfig',
        GLOBAL_FAVORITES: 'keeper.globalFavorites',
        GLOBAL_RECENT: 'keeper.globalRecent'
    };

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    async initialize(): Promise<void> {
        await this.loadConfigurations();
        await this.loadActiveConfiguration();
        
        // Try to authenticate existing configurations
        for (const config of this.configurations.values()) {
            try {
                await this.authenticateConfiguration(config.id);
            } catch (error) {
                console.log(`Failed to auto-authenticate config ${config.name}: ${error}`);
                // Continue with other configurations
            }
        }
    }

    async addConfiguration(authInput: string, userProvidedName?: string): Promise<string> {
        const configId = uuidv4();
        const authType = this.detectAuthType(authInput);
        
        // Create configuration
        const config: KSMConfiguration = {
            id: configId,
            name: userProvidedName || 'New Configuration',
            displayName: userProvidedName || 'New Configuration',
            hostname: '', // Will be set by SDK
            authType,
            isAuthenticated: false,
            lastAuth: undefined,
            secretCount: 0,
            folders: [],
            records: []
        };

        // Store auth credentials securely
        await this.context.secrets.store(`${configId}.authInput`, authInput);

        // Add to configurations FIRST (before authentication)
        this.configurations.set(configId, config);

        // Initialize storage and authenticate
        try {
            await this.authenticateConfiguration(configId);
            
            // Try to get app name from KSM SDK
            const appName = await this.getAppNameFromSDK(configId);
            if (appName) {
                config.name = appName;
                config.displayName = appName;
            }
        } catch (error) {
            // Remove the configuration if authentication fails
            this.configurations.delete(configId);
            await this.context.secrets.delete(`${configId}.authInput`);
            console.error('Failed to authenticate configuration:', error);
            throw new Error(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
        
        // Set as active if it's the first configuration
        if (this.configurations.size === 1) {
            this.activeConfigId = configId;
            await this.saveActiveConfiguration();
            this._onDidChangeActiveConfiguration.fire(config);
        }

        await this.saveConfigurations();
        this._onDidChangeConfigurations.fire(Array.from(this.configurations.values()));
        
        return configId;
    }

    async removeConfiguration(configId: string): Promise<void> {
        const config = this.configurations.get(configId);
        if (!config) {
            throw new Error(`Configuration with ID ${configId} not found`);
        }

        // Remove from configurations
        this.configurations.delete(configId);
        
        // Remove storage
        if (this.storageMap.has(configId)) {
            this.storageMap.delete(configId);
        }
        
        // Remove stored credentials
        await this.context.secrets.delete(`${configId}.authInput`);
        
        // Update active config if necessary
        if (this.activeConfigId === configId) {
            const remaining = Array.from(this.configurations.values());
            this.activeConfigId = remaining.length > 0 ? remaining[0].id : undefined;
            await this.saveActiveConfiguration();
            this._onDidChangeActiveConfiguration.fire(this.getActiveConfiguration());
        }

        await this.saveConfigurations();
        this._onDidChangeConfigurations.fire(Array.from(this.configurations.values()));
    }

    async authenticateConfiguration(configId: string): Promise<void> {
        const config = this.configurations.get(configId);
        if (!config) {
            throw new Error(`Configuration with ID ${configId} not found`);
        }

        // Get stored credentials
        const authInput = await this.context.secrets.get(`${configId}.authInput`);
        
        if (!authInput) {
            throw new Error('No stored credentials found for configuration');
        }

        // Initialize storage - let SDK handle everything
        let storage: any;
        try {
            if (config.authType === 'base64Config') {
                // Handle base64 config - SDK creates storage from config
                console.log('Initializing base64 config...');
                const { loadJsonConfig } = await import("@keeper-security/secrets-manager-core");
                storage = loadJsonConfig(authInput);
            } else {
                // Handle one-time token - SDK creates storage from token and converts to base64
                console.log('Initializing one-time token...');
                storage = inMemoryStorage({});
                await initializeStorage(storage, authInput);
                
                // After initialization, the SDK has converted the token to base64 config
                // Update the stored auth type and save the base64 config
                config.authType = 'base64Config';
                
                // Get the base64 config from storage and save it
                const hostname = await storage.getString('hostname');
                const clientId = await storage.getString('clientId');
                const privateKey = await storage.getString('privateKey');
                const appKey = await storage.getString('appKey');
                const serverPublicKeyId = await storage.getString('serverPublicKeyId');
                
                const configObj = {
                    hostname,
                    clientId,
                    privateKey,
                    appKey,
                    serverPublicKeyId
                };
                
                const base64Config = Buffer.from(JSON.stringify(configObj)).toString('base64');
                await this.context.secrets.store(`${configId}.authInput`, base64Config);
                
                console.log('One-time token converted to base64 config');
            }
        } catch (error) {
            console.error('Failed to initialize storage:', error);
            throw new Error(`Failed to initialize storage: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }

        // Test connection by fetching secrets
        const options: SecretManagerOptions = { storage };
        const result: KeeperSecrets = await getSecrets(options);
        
        // Update configuration
        config.isAuthenticated = true;
        config.lastAuth = new Date();
        config.secretCount = result.records.length;
        config.records = result.records;
        config.folders = this.organizeFolders(result.records);
        
        // Store the working storage
        this.storageMap.set(configId, storage);
        
        // Save configuration
        await this.saveConfigurations();
        this._onDidChangeConfigurations.fire(Array.from(this.configurations.values()));
    }

    async refreshConfiguration(configId: string): Promise<void> {
        const storage = this.storageMap.get(configId);
        if (!storage) {
            throw new Error('Configuration not authenticated');
        }

        const options: SecretManagerOptions = { storage };
        const result: KeeperSecrets = await getSecrets(options);
        
        const config = this.configurations.get(configId);
        if (config) {
            config.secretCount = result.records.length;
            config.records = result.records;
            config.folders = this.organizeFolders(result.records);
            config.lastAuth = new Date();
            
            await this.saveConfigurations();
            this._onDidChangeConfigurations.fire(Array.from(this.configurations.values()));
        }
    }

    getConfigurations(): KSMConfiguration[] {
        return Array.from(this.configurations.values());
    }

    getConfiguration(configId: string): KSMConfiguration | undefined {
        return this.configurations.get(configId);
    }

    getActiveConfiguration(): KSMConfiguration | undefined {
        return this.activeConfigId ? this.configurations.get(this.activeConfigId) : undefined;
    }

    async setActiveConfiguration(configId: string): Promise<void> {
        if (!this.configurations.has(configId)) {
            throw new Error(`Configuration with ID ${configId} not found`);
        }

        this.activeConfigId = configId;
        await this.saveActiveConfiguration();
        this._onDidChangeActiveConfiguration.fire(this.getActiveConfiguration());
    }

    getStorage(configId: string): any {
        return this.storageMap.get(configId);
    }

    async createRecord(configId: string, folderUid: string, recordData: any): Promise<string> {
        const storage = this.storageMap.get(configId);
        if (!storage) {
            throw new Error('Configuration not authenticated');
        }

        const { createSecret } = await import("@keeper-security/secrets-manager-core");
        const options = { storage };
        
        const recordUid = await createSecret(options, folderUid, recordData);
        
        // Refresh configuration
        await this.refreshConfiguration(configId);
        
        return recordUid;
    }

    async resolveNotation(notation: string, configId?: string): Promise<string> {
        const activeConfig = configId ? this.getConfiguration(configId) : this.getActiveConfiguration();
        if (!activeConfig || !activeConfig.records) {
            throw new Error('No active configuration or records loaded');
        }

        // Parse the notation
        const match = notation.match(/keeper:\/\/([^\/]+)\/field\/([^}]+)/);
        if (!match) {
            throw new Error('Invalid keeper notation format');
        }

        const uid = match[1];
        const fieldName = match[2];

        // Find the record
        const record = activeConfig.records.find(r => r.recordUid === uid);
        if (!record) {
            throw new Error(`Record with UID ${uid} not found`);
        }

        // Find the field
        const field = record.data.fields.find((f: any) => f.label === fieldName || f.type === fieldName);
        if (!field) {
            throw new Error(`Field ${fieldName} not found in record ${uid}`);
        }

        return field.value && field.value.length > 0 ? field.value[0] : '';
    }

    private async loadConfigurations(): Promise<void> {
        const stored = this.context.globalState.get<StoredConfigurations>(this.STORAGE_KEYS.CONFIGURATIONS);
        if (stored && stored.configurations) {
            for (const config of stored.configurations) {
                this.configurations.set(config.id, config);
            }
        }
    }

    private async saveConfigurations(): Promise<void> {
        const stored: StoredConfigurations = {
            configurations: Array.from(this.configurations.values())
        };
        await this.context.globalState.update(this.STORAGE_KEYS.CONFIGURATIONS, stored);
    }

    private async loadActiveConfiguration(): Promise<void> {
        this.activeConfigId = this.context.globalState.get<string>(this.STORAGE_KEYS.ACTIVE_CONFIG);
    }

    private async saveActiveConfiguration(): Promise<void> {
        await this.context.globalState.update(this.STORAGE_KEYS.ACTIVE_CONFIG, this.activeConfigId);
    }

    private detectAuthType(authInput: string): 'oneTimeToken' | 'base64Config' {
        if (authInput.startsWith('eyJ') || authInput.startsWith('{')) {
            return 'base64Config';
        } else if (authInput.includes(':') && (authInput.startsWith('US:') || authInput.startsWith('EU:') || authInput.startsWith('AU:') || authInput.includes('.'))) {
            return 'oneTimeToken';
        } else {
            return 'base64Config';
        }
    }

    private async getAppNameFromSDK(configId: string): Promise<string | null> {
        const storage = this.storageMap.get(configId);
        if (!storage) {
            return null;
        }

        try {
            const options: SecretManagerOptions = { storage };
            const result: KeeperSecrets = await getSecrets(options);
            
            // Check if the KeeperSecrets object has app metadata
            if (result.appData && result.appData.title) {
                return result.appData.title;
            }
        } catch (error) {
            console.log(`Could not get app name from SDK: ${error}`);
        }

        return null;
    }


    private organizeFolders(records: KeeperRecord[]): KSMFolder[] {
        const folders: Map<string, KSMFolder> = new Map();
        const rootFolders: KSMFolder[] = [];

        // First pass: create folder structure
        for (const record of records) {
            const folderUid = record.folderUid || 'root';
            
            if (!folders.has(folderUid)) {
                folders.set(folderUid, {
                    uid: folderUid,
                    name: folderUid === 'root' ? 'Root' : `Folder ${folderUid}`,
                    type: 'regular', // TODO: detect shared vs regular folders
                    records: [],
                    subfolders: []
                });
            }

            const folder = folders.get(folderUid)!;
            folder.records.push({
                uid: record.recordUid,
                title: record.data.title || record.recordUid,
                folderUid: folderUid,
                recordUid: record.recordUid,
                data: record.data,
                fields: record.data.fields.map((f: any) => ({
                    type: f.type,
                    label: f.label,
                    value: f.value
                })),
                type: record.data.type || 'login'
            });
        }

        // For now, all folders are root level
        // TODO: implement proper folder hierarchy detection
        for (const folder of folders.values()) {
            if (folder.uid !== 'root') {
                rootFolders.push(folder);
            }
        }

        // Add root folder if it has records
        const rootFolder = folders.get('root');
        if (rootFolder && rootFolder.records.length > 0) {
            rootFolders.unshift(rootFolder);
        }

        return rootFolders;
    }
}