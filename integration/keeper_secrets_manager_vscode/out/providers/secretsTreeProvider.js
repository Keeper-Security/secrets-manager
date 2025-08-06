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
exports.AddConfigurationTreeItem = exports.ActionTreeItem = exports.FieldTreeItem = exports.RecordTreeItem = exports.FolderTreeItem = exports.ConfigurationTreeItem = exports.TreeItem = exports.SecretsTreeProvider = void 0;
const vscode = __importStar(require("vscode"));
class SecretsTreeProvider {
    constructor(configurationManager) {
        this.configurationManager = configurationManager;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        console.log('SecretsTreeProvider constructor called');
        // Listen for configuration changes
        this.configurationManager.onDidChangeConfigurations(() => {
            this.refresh();
        });
    }
    refresh() {
        this._onDidChangeTreeData.fire();
    }
    getTreeItem(element) {
        return element;
    }
    getChildren(element) {
        console.log('getChildren called with element:', element);
        if (!element) {
            // Return root level items (configurations + add button)
            const rootElements = this.getRootElements();
            console.log('Returning root elements:', rootElements);
            return Promise.resolve(rootElements);
        }
        if (element instanceof ConfigurationTreeItem) {
            return Promise.resolve(this.getConfigurationChildren(element));
        }
        if (element instanceof FolderTreeItem) {
            return Promise.resolve(this.getFolderChildren(element));
        }
        if (element instanceof RecordTreeItem) {
            return Promise.resolve(this.getRecordChildren(element));
        }
        return Promise.resolve([]);
    }
    getRootElements() {
        const configurations = this.configurationManager.getConfigurations();
        const items = [];
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
    getConfigurationChildren(configItem) {
        const config = configItem.configuration;
        const items = [];
        if (!config.isAuthenticated) {
            // Show authentication prompt
            items.push(new ActionTreeItem('Click to authenticate', 'Authenticate to view secrets', 'authenticate', config.id, new vscode.ThemeIcon('key')));
            return items;
        }
        if (!config.folders || config.folders.length === 0) {
            // Show loading or empty state
            items.push(new ActionTreeItem('No folders found', 'Click to refresh', 'refresh', config.id, new vscode.ThemeIcon('refresh')));
            return items;
        }
        // Add folder items
        for (const folder of config.folders) {
            items.push(new FolderTreeItem(folder, config.id));
        }
        return items;
    }
    getFolderChildren(folderItem) {
        const folder = folderItem.folder;
        const items = [];
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
    getRecordChildren(recordItem) {
        const record = recordItem.record;
        const items = [];
        // Add field items - check both possible field locations
        const fields = record.fields || record.data?.fields || [];
        // Use the correct record UID property
        const recordUid = record.uid || record.recordUid;
        for (const field of fields) {
            items.push(new FieldTreeItem(field, recordUid, recordItem.configId));
        }
        return items;
    }
}
exports.SecretsTreeProvider = SecretsTreeProvider;
class TreeItem extends vscode.TreeItem {
    constructor(label, collapsibleState) {
        super(label, collapsibleState);
        this.label = label;
        this.collapsibleState = collapsibleState;
    }
}
exports.TreeItem = TreeItem;
class ConfigurationTreeItem extends TreeItem {
    constructor(configuration) {
        super(configuration.displayName, vscode.TreeItemCollapsibleState.Expanded);
        this.configuration = configuration;
        this.id = configuration.id;
        this.tooltip = this.buildTooltip();
        this.contextValue = configuration.isAuthenticated ? 'configuration.authenticated' : 'configuration.unauthenticated';
        this.iconPath = this.getIcon();
        this.description = this.getDescription();
    }
    buildTooltip() {
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
    getIcon() {
        if (this.configuration.isAuthenticated) {
            return new vscode.ThemeIcon('server', new vscode.ThemeColor('charts.green'));
        }
        else {
            return new vscode.ThemeIcon('server', new vscode.ThemeColor('charts.red'));
        }
    }
    getDescription() {
        if (this.configuration.isAuthenticated) {
            return `${this.configuration.secretCount || 0} secrets`;
        }
        else {
            return 'not authenticated';
        }
    }
}
exports.ConfigurationTreeItem = ConfigurationTreeItem;
class FolderTreeItem extends TreeItem {
    constructor(folder, configId) {
        super(folder.name, vscode.TreeItemCollapsibleState.Collapsed);
        this.folder = folder;
        this.configId = configId;
        this.id = `${configId}-${folder.uid}`;
        this.tooltip = this.buildTooltip();
        this.contextValue = `folder.${folder.type}`;
        this.iconPath = this.getIcon();
        this.description = this.getDescription();
    }
    buildTooltip() {
        const folder = this.folder;
        const lines = [
            `Name: ${folder.name}`,
            `Type: ${folder.type === 'shared' ? 'Shared Folder' : 'Regular Folder'}`,
            `Records: ${folder.records.length}`,
            `Subfolders: ${folder.subfolders.length}`
        ];
        return lines.join('\n');
    }
    getIcon() {
        if (this.folder.type === 'shared') {
            return new vscode.ThemeIcon('folder-opened', new vscode.ThemeColor('charts.blue'));
        }
        else {
            return new vscode.ThemeIcon('folder');
        }
    }
    getDescription() {
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
exports.FolderTreeItem = FolderTreeItem;
class RecordTreeItem extends TreeItem {
    constructor(record, configId) {
        super(record.title, vscode.TreeItemCollapsibleState.Collapsed);
        this.record = record;
        this.configId = configId;
        this.id = `${configId}-${record.uid || record.recordUid}`;
        this.tooltip = this.buildTooltip();
        this.contextValue = `record.${record.type}`;
        this.iconPath = this.getIcon();
        this.description = this.getDescription();
    }
    buildTooltip() {
        const record = this.record;
        const fields = record.fields || record.data?.fields || [];
        const uid = record.uid || record.recordUid;
        const lines = [
            `Title: ${record.title}`,
            `Type: ${record.type}`,
            `UID: ${uid}`,
            `Fields: ${fields.length}`
        ];
        return lines.join('\n');
    }
    getIcon() {
        switch (this.record.type.toLowerCase()) {
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
            default:
                return new vscode.ThemeIcon('symbol-key');
        }
    }
    getDescription() {
        const fields = this.record.fields || this.record.data?.fields || [];
        return `${fields.length} field${fields.length === 1 ? '' : 's'}`;
    }
}
exports.RecordTreeItem = RecordTreeItem;
class FieldTreeItem extends TreeItem {
    constructor(field, recordId, configId) {
        super(field.label || field.type, vscode.TreeItemCollapsibleState.None);
        this.field = field;
        this.recordId = recordId;
        this.configId = configId;
        this.id = `${configId}-${recordId}-${field.type}`;
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
    buildTooltip() {
        const field = this.field;
        const lines = [
            `Label: ${field.label}`,
            `Type: ${field.type}`,
            `Value: ${this.shouldShowValue() ? field.value.join(', ') : '••••••••'}`
        ];
        return lines.join('\n');
    }
    getIcon() {
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
    getDescription() {
        if (this.shouldShowValue()) {
            return this.field.value.join(', ');
        }
        else {
            return '••••••••';
        }
    }
    shouldShowValue() {
        // Check if secret values should be shown based on settings
        const config = vscode.workspace.getConfiguration('keeper');
        const showSecretValues = config.get('showSecretValues', false);
        // Never show password fields in description for security
        if (this.field.type.toLowerCase() === 'password') {
            return false;
        }
        return showSecretValues;
    }
}
exports.FieldTreeItem = FieldTreeItem;
class ActionTreeItem extends TreeItem {
    constructor(label, tooltip, action, configId, iconPath) {
        super(label, vscode.TreeItemCollapsibleState.None);
        this.tooltip = tooltip;
        this.action = action;
        this.configId = configId;
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
exports.ActionTreeItem = ActionTreeItem;
class AddConfigurationTreeItem extends TreeItem {
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
exports.AddConfigurationTreeItem = AddConfigurationTreeItem;
//# sourceMappingURL=secretsTreeProvider.js.map