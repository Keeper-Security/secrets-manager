import * as vscode from 'vscode';
import { ConfigurationManager, KSMConfiguration, KSMFolder, KSMRecord } from '../services/configurationManager';

export class SecretsTreeProvider implements vscode.TreeDataProvider<TreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<TreeItem | undefined | null | void>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor(
        private configurationManager: ConfigurationManager,
        private outputChannel?: vscode.OutputChannel
    ) {
        this.log('='.repeat(50));
        this.log('[SecretsTreeProvider] Constructor called');
        this.log('='.repeat(50));
        console.log('[SecretsTreeProvider] Constructor called - console.log test');
        
        // Listen for configuration changes
        this.configurationManager.onDidChangeConfigurations(() => {
            this.log('[SecretsTreeProvider] Configuration changed, refreshing tree');
            this.refresh();
        });
    }
    
    private log(message: string): void {
        console.log(message);
        if (this.outputChannel) {
            this.outputChannel.appendLine(message);
        }
    }

    refresh(): void {
        this.log('[SecretsTreeProvider] Refresh called');
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: TreeItem): vscode.TreeItem {
        try {
            this.log('[SecretsTreeProvider.getTreeItem] Called with element: ' + JSON.stringify({
                id: element.id,
                label: element.label,
                contextValue: element.contextValue,
                type: element.constructor.name,
                hasCommand: !!element.command
            }, null, 2));
            
            if (element.command) {
                console.log('[SecretsTreeProvider.getTreeItem] Element has command:', {
                    command: element.command.command,
                    title: element.command.title,
                    argumentsCount: element.command.arguments?.length
                });
            }
            
            return element;
        } catch (error) {
            console.error('[SecretsTreeProvider.getTreeItem] ERROR:', error);
            throw error;
        }
    }

    getChildren(element?: TreeItem): Thenable<TreeItem[]> {
        // Add immediate visual feedback
        if (!element) {
            vscode.window.showInformationMessage('[DEBUG] TreeView getChildren called for ROOT');
        } else {
            vscode.window.showInformationMessage(`[DEBUG] TreeView getChildren called for: ${element.label}`);
        }
        
        try {
            this.log('[SecretsTreeProvider.getChildren] Called with element: ' + (element ? JSON.stringify({
                id: element.id,
                label: element.label,
                type: element.constructor.name
            }, null, 2) : 'undefined (root)'));
            
            if (!element) {
                // Return root level items (configurations + add button)
                const rootElements = this.getRootElements();
                console.log('[SecretsTreeProvider.getChildren] Returning root elements:', rootElements.map(e => ({
                    id: e.id,
                    label: e.label,
                    type: e.constructor.name
                })));
                return Promise.resolve(rootElements);
            }

            if (element instanceof ConfigurationTreeItem) {
                console.log('[SecretsTreeProvider.getChildren] Getting children for ConfigurationTreeItem');
                const children = this.getConfigurationChildren(element);
                console.log('[SecretsTreeProvider.getChildren] ConfigurationTreeItem children count:', children.length);
                return Promise.resolve(children);
            }

            if (element instanceof FolderTreeItem) {
                console.log('[SecretsTreeProvider.getChildren] Getting children for FolderTreeItem');
                const children = this.getFolderChildren(element);
                console.log('[SecretsTreeProvider.getChildren] FolderTreeItem children count:', children.length);
                return Promise.resolve(children);
            }

            if (element instanceof RecordTreeItem) {
                this.log('[SecretsTreeProvider.getChildren] Getting children for RecordTreeItem: ' + JSON.stringify({
                    recordId: element.id,
                    recordTitle: element.record.data?.title || element.record.title,
                    recordUid: element.record.recordUid || element.record.uid,
                    configId: element.configId,
                    recordStructure: {
                        hasData: !!element.record.data,
                        hasDirectFields: !!element.record.fields,
                        hasDataFields: !!element.record.data?.fields
                    }
                }, null, 2));
                
                // Show message for debugging
                vscode.window.showInformationMessage(`[DEBUG] Expanding record: ${element.record.data?.title || element.record.title || 'Unknown'}`);
                
                const children = this.getRecordChildren(element);
                this.log('[SecretsTreeProvider.getChildren] RecordTreeItem children count: ' + children.length);
                return Promise.resolve(children);
            }

            console.log('[SecretsTreeProvider.getChildren] Unknown element type, returning empty array');
            return Promise.resolve([]);
        } catch (error) {
            console.error('[SecretsTreeProvider.getChildren] ERROR:', error);
            console.error('[SecretsTreeProvider.getChildren] Stack trace:', error.stack);
            return Promise.resolve([]);
        }
    }

    private getRootElements(): TreeItem[] {
        const configurations = this.configurationManager.getConfigurations();
        const items: TreeItem[] = [];

        console.log('Getting root elements, configurations:', configurations.length);

        // Add configuration items
        for (const config of configurations) {
            console.log('Adding configuration:', config.name);
            items.push(new ConfigurationTreeItem(config));
        }

        // Add "Add New Configuration" item
        items.push(new AddConfigurationTreeItem());

        console.log('Total root items:', items.length);
        return items;
    }

    private getConfigurationChildren(configItem: ConfigurationTreeItem): TreeItem[] {
        const config = configItem.configuration;
        const items: TreeItem[] = [];

        if (!config.isAuthenticated) {
            // Show authentication prompt
            items.push(new ActionTreeItem(
                'Click to authenticate',
                'Authenticate to view secrets',
                'authenticate',
                config.id,
                new vscode.ThemeIcon('key')
            ));
            return items;
        }

        if (!config.folders || config.folders.length === 0) {
            // Show loading or empty state
            items.push(new ActionTreeItem(
                'No folders found',
                'Click to refresh',
                'refresh',
                config.id,
                new vscode.ThemeIcon('refresh')
            ));
            return items;
        }

        // Add folder items
        for (const folder of config.folders) {
            items.push(new FolderTreeItem(folder, config.id));
        }

        return items;
    }

    private getFolderChildren(folderItem: FolderTreeItem): TreeItem[] {
        const folder = folderItem.folder;
        const items: TreeItem[] = [];

        // Add subfolder items
        for (const subfolder of folder.subfolders) {
            items.push(new FolderTreeItem(subfolder, folderItem.configId));
        }

        // Add record items
        for (const record of folder.records) {
            items.push(new RecordTreeItem(record, folderItem.configId));
        }

        return items;
    }

    private getRecordChildren(recordItem: RecordTreeItem): TreeItem[] {
        console.log('[SecretsTreeProvider.getRecordChildren] Called with record:', {
            title: recordItem.record.data?.title || recordItem.record.title,
            uid: recordItem.record.uid,
            recordUid: recordItem.record.recordUid,
            hasFields: !!recordItem.record.fields,
            hasDataFields: !!recordItem.record.data?.fields,
            configId: recordItem.configId,
            recordData: recordItem.record.data
        });

        const record = recordItem.record;
        const items: TreeItem[] = [];

        // Add field items - check both possible field locations
        const fields = record.data?.fields || record.fields || [];
        
        console.log('[SecretsTreeProvider.getRecordChildren] Fields found:', {
            fieldsCount: fields.length,
            fieldTypes: fields.map(f => ({ type: f.type, label: f.label })),
            fromRecordFields: !!record.fields,
            fromDataFields: !!record.data?.fields
        });
        
        // Use the correct record UID property
        const recordUid = record.recordUid || record.uid;
        console.log('[SecretsTreeProvider.getRecordChildren] Using recordUid:', recordUid);
        
        for (const field of fields) {
            console.log('[SecretsTreeProvider.getRecordChildren] Creating FieldTreeItem for field:', {
                type: field.type,
                label: field.label,
                recordUid: recordUid,
                configId: recordItem.configId,
                hasValue: !!field.value,
                valueLength: field.value?.length
            });
            const fieldItem = new FieldTreeItem(field, recordUid, recordItem.configId);
            console.log('[SecretsTreeProvider.getRecordChildren] Created FieldTreeItem:', {
                id: fieldItem.id,
                label: fieldItem.label,
                contextValue: fieldItem.contextValue
            });
            items.push(fieldItem);
        }

        console.log('[SecretsTreeProvider.getRecordChildren] Returning items:', items.length);
        return items;
    }
}

export abstract class TreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState
    ) {
        super(label, collapsibleState);
    }
}

export class ConfigurationTreeItem extends TreeItem {
    constructor(public readonly configuration: KSMConfiguration) {
        super(
            configuration.displayName,
            vscode.TreeItemCollapsibleState.Expanded
        );

        this.id = configuration.id;
        this.tooltip = this.buildTooltip();
        this.contextValue = configuration.isAuthenticated ? 'configuration.authenticated' : 'configuration.unauthenticated';
        this.iconPath = this.getIcon();
        this.description = this.getDescription();
    }

    private buildTooltip(): string {
        const config = this.configuration;
        const lines = [
            `Name: ${config.name}`,
            `Hostname: ${config.hostname}`,
            `Type: ${config.authType}`,
            `Status: ${config.isAuthenticated ? 'Authenticated' : 'Not authenticated'}`
        ];

        if (config.isAuthenticated) {
            lines.push(`Secrets: ${config.secretCount || 0}`);
            if (config.lastAuth) {
                lines.push(`Last Auth: ${config.lastAuth.toLocaleString()}`);
            }
        }

        return lines.join('\n');
    }

    private getIcon(): vscode.ThemeIcon {
        if (this.configuration.isAuthenticated) {
            return new vscode.ThemeIcon('server', new vscode.ThemeColor('charts.green'));
        } else {
            return new vscode.ThemeIcon('server', new vscode.ThemeColor('charts.red'));
        }
    }

    private getDescription(): string {
        if (this.configuration.isAuthenticated) {
            return `${this.configuration.secretCount || 0} secrets`;
        } else {
            return 'not authenticated';
        }
    }
}

export class FolderTreeItem extends TreeItem {
    constructor(
        public readonly folder: KSMFolder,
        public readonly configId: string
    ) {
        super(
            folder.name,
            vscode.TreeItemCollapsibleState.Collapsed
        );

        this.id = `${configId}-${folder.uid}`;
        this.tooltip = this.buildTooltip();
        this.contextValue = `folder.${folder.type}`;
        this.iconPath = this.getIcon();
        this.description = this.getDescription();
    }

    private buildTooltip(): string {
        const folder = this.folder;
        const lines = [
            `Name: ${folder.name}`,
            `Type: ${folder.type === 'shared' ? 'Shared Folder' : 'Regular Folder'}`,
            `Records: ${folder.records.length}`,
            `Subfolders: ${folder.subfolders.length}`
        ];

        return lines.join('\n');
    }

    private getIcon(): vscode.ThemeIcon {
        if (this.folder.type === 'shared') {
            return new vscode.ThemeIcon('folder-opened', new vscode.ThemeColor('charts.blue'));
        } else {
            return new vscode.ThemeIcon('folder');
        }
    }

    private getDescription(): string {
        const recordCount = this.folder.records.length;
        const subfolderCount = this.folder.subfolders.length;
        const parts = [];

        if (recordCount > 0) {
            parts.push(`${recordCount} secret${recordCount === 1 ? '' : 's'}`);
        }

        if (subfolderCount > 0) {
            parts.push(`${subfolderCount} folder${subfolderCount === 1 ? '' : 's'}`);
        }

        return parts.join(', ');
    }
}

export class RecordTreeItem extends TreeItem {
    constructor(
        public readonly record: KSMRecord,
        public readonly configId: string
    ) {
        // Handle both possible record structures
        const title = record.data?.title || record.title || 'Untitled';
        super(
            title,
            vscode.TreeItemCollapsibleState.Collapsed
        );

        const recordUid = record.recordUid || record.uid;
        // Ensure ID is properly encoded to avoid VS Code parsing issues
        const sanitizedRecordUid = recordUid.replace(/[^a-zA-Z0-9_-]/g, '_');
        this.id = `${configId}-${sanitizedRecordUid}`;
        console.log('[RecordTreeItem] Created with:', {
            originalRecordUid: recordUid,
            sanitizedRecordUid: sanitizedRecordUid,
            finalId: this.id,
            title: title,
            configId: configId,
            recordType: record.data?.type || record.type,
            hasData: !!record.data,
            hasDirectTitle: !!record.title
        });
        this.tooltip = this.buildTooltip();
        this.contextValue = `record.${record.data?.type || record.type || 'general'}`;
        this.iconPath = this.getIcon();
        this.description = this.getDescription();
    }

    private buildTooltip(): string {
        const record = this.record;
        const fields = record.data?.fields || record.fields || [];
        const uid = record.recordUid || record.uid;
        const title = record.data?.title || record.title || 'Untitled';
        const type = record.data?.type || record.type || 'general';
        
        const lines = [
            `Title: ${title}`,
            `Type: ${type}`,
            `UID: ${uid}`,
            `Fields: ${fields.length}`
        ];

        return lines.join('\n');
    }

    private getIcon(): vscode.ThemeIcon {
        const type = (this.record.data?.type || this.record.type || 'general').toLowerCase();
        switch (type) {
            case 'login':
                return new vscode.ThemeIcon('key');
            case 'password':
                return new vscode.ThemeIcon('lock');
            case 'database':
                return new vscode.ThemeIcon('database');
            case 'server':
                return new vscode.ThemeIcon('server');
            case 'file':
                return new vscode.ThemeIcon('file');
            case 'note':
                return new vscode.ThemeIcon('note');
            case 'pamuser':
                return new vscode.ThemeIcon('person');
            default:
                return new vscode.ThemeIcon('symbol-key');
        }
    }

    private getDescription(): string {
        const fields = this.record.data?.fields || this.record.fields || [];
        return `${fields.length} field${fields.length === 1 ? '' : 's'}`;
    }
}

export class FieldTreeItem extends TreeItem {
    constructor(
        public readonly field: { type: string; label: string; value: string[] },
        public readonly recordId: string,
        public readonly configId: string
    ) {
        super(
            field.label || field.type,
            vscode.TreeItemCollapsibleState.None
        );

        // Ensure ID is properly encoded to avoid VS Code parsing issues
        const sanitizedRecordId = recordId.replace(/[^a-zA-Z0-9_-]/g, '_');
        const sanitizedFieldType = field.type.replace(/[^a-zA-Z0-9_-]/g, '_');
        this.id = `${configId}-${sanitizedRecordId}-${sanitizedFieldType}`;
        console.log('[FieldTreeItem] Created with:', {
            originalRecordId: recordId,
            sanitizedRecordId: sanitizedRecordId,
            fieldType: field.type,
            sanitizedFieldType: sanitizedFieldType,
            finalId: this.id,
            fieldLabel: field.label,
            configId: configId
        });
        this.tooltip = this.buildTooltip();
        this.contextValue = field.type === 'file' ? `field.file` : `field.${field.type}`;
        this.iconPath = this.getIcon();
        this.description = this.getDescription();
        
        // Add command to copy on click
        this.command = {
            command: 'keeper.tree.copySecret',
            title: 'Copy Secret',
            arguments: [this]
        };
    }

    private buildTooltip(): string {
        const field = this.field;
        const lines = [
            `Label: ${field.label}`,
            `Type: ${field.type}`,
            `Value: ${this.shouldShowValue() ? field.value.join(', ') : '••••••••'}`
        ];

        return lines.join('\n');
    }

    private getIcon(): vscode.ThemeIcon {
        switch (this.field.type.toLowerCase()) {
            case 'login':
            case 'username':
                return new vscode.ThemeIcon('person');
            case 'password':
                return new vscode.ThemeIcon('lock');
            case 'email':
                return new vscode.ThemeIcon('mail');
            case 'url':
                return new vscode.ThemeIcon('link');
            case 'phone':
                return new vscode.ThemeIcon('device-mobile');
            case 'file':
                return new vscode.ThemeIcon('file-binary');
            case 'text':
            case 'note':
                return new vscode.ThemeIcon('note');
            case 'date':
                return new vscode.ThemeIcon('calendar');
            case 'address':
                return new vscode.ThemeIcon('location');
            default:
                return new vscode.ThemeIcon('symbol-field');
        }
    }

    private getDescription(): string {
        if (this.shouldShowValue()) {
            return this.field.value.join(', ');
        } else {
            return '••••••••';
        }
    }

    private shouldShowValue(): boolean {
        // Check if secret values should be shown based on settings
        const config = vscode.workspace.getConfiguration('keeper');
        const showSecretValues = config.get<boolean>('showSecretValues', false);
        
        // Never show password fields in description for security
        if (this.field.type.toLowerCase() === 'password') {
            return false;
        }

        return showSecretValues;
    }
}

export class ActionTreeItem extends TreeItem {
    constructor(
        label: string,
        public readonly tooltip: string,
        public readonly action: string,
        public readonly configId?: string,
        iconPath?: vscode.ThemeIcon
    ) {
        super(label, vscode.TreeItemCollapsibleState.None);

        this.tooltip = tooltip;
        this.iconPath = iconPath;
        this.contextValue = `action.${action}`;
        this.command = {
            command: `keeper.tree.${action}`,
            title: label,
            arguments: [this.configId]
        };
    }
}

export class AddConfigurationTreeItem extends TreeItem {
    constructor() {
        super('➕ Add New Configuration', vscode.TreeItemCollapsibleState.None);

        this.tooltip = 'Add a new KSM configuration';
        this.iconPath = new vscode.ThemeIcon('add');
        this.contextValue = 'action.addConfiguration';
        this.command = {
            command: 'keeper.tree.addConfiguration',
            title: 'Add New Configuration'
        };
    }
}