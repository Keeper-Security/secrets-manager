import * as vscode from 'vscode';
import { KSMService } from './services/ksmService';
import { SecretsProvider } from './providers/secretsProvider';
import { NotationProvider } from './providers/notationProvider';
import { EnvSyncService } from './services/envSyncService';
import { CodeGenerationService } from './services/codeGenerationService';
import { QuickAccessService } from './services/quickAccessService';
import { TerminalDetectionService } from './services/terminalDetectionService';
import { ConfigurationManager } from './services/configurationManager';
import { SecretsTreeProvider } from './providers/secretsTreeProvider';

let ksmService: KSMService;
let secretsProvider: SecretsProvider;
let notationProvider: NotationProvider;
let envSyncService: EnvSyncService;
let codeGenerationService: CodeGenerationService;
let quickAccessService: QuickAccessService;
let terminalDetectionService: TerminalDetectionService;
let configurationManager: ConfigurationManager;
let secretsTreeProvider: SecretsTreeProvider;

export function activate(context: vscode.ExtensionContext) {
    console.log('='.repeat(80));
    console.log('[KEEPER] Extension activation started - WITH ENHANCED DEBUG');
    console.log('='.repeat(80));
    
    // Create output channel for debugging
    const outputChannel = vscode.window.createOutputChannel('Keeper Secrets Manager Debug');
    outputChannel.appendLine('='.repeat(80));
    outputChannel.appendLine('[KEEPER DEBUG] Extension activated - Enhanced debug logging enabled');
    outputChannel.appendLine(`[KEEPER DEBUG] Time: ${new Date().toISOString()}`);
    outputChannel.appendLine('='.repeat(80));
    outputChannel.show();
    
    // Also show a notification
    vscode.window.showInformationMessage('Keeper Extension: Debug mode active - check Output panel');
    
    // Add global error handler for unhandled exceptions
    process.on('uncaughtException', (error) => {
        console.error('Uncaught Exception in extension:', error);
        outputChannel.appendLine(`Uncaught Exception: ${error.message}`);
        outputChannel.appendLine(`Stack: ${error.stack}`);
    });
    
    process.on('unhandledRejection', (reason, promise) => {
        console.error('Unhandled Promise Rejection in extension:', reason);
        outputChannel.appendLine(`Unhandled Promise Rejection: ${reason}`);
    });

    // Initialize services
    configurationManager = new ConfigurationManager(context);
    ksmService = new KSMService(context, configurationManager);
    secretsProvider = new SecretsProvider(ksmService);
    notationProvider = new NotationProvider(ksmService);
    envSyncService = new EnvSyncService(ksmService);
    codeGenerationService = new CodeGenerationService(ksmService);
    quickAccessService = new QuickAccessService(ksmService, context);
    terminalDetectionService = new TerminalDetectionService(quickAccessService);
    secretsTreeProvider = new SecretsTreeProvider(configurationManager, outputChannel);

    // Initialize configuration manager
    configurationManager.initialize();

    // Register tree view
    console.log('[Extension] Registering TreeView...');
    console.log('[Extension] TreeProvider instance:', secretsTreeProvider);
    try {
        console.log('[Extension] Creating tree view with id: keeper.secretsTree');
        const treeView = vscode.window.createTreeView('keeper.secretsTree', {
            treeDataProvider: secretsTreeProvider,
            showCollapseAll: true,
            canSelectMany: false
        });
        console.log('[Extension] TreeView registered successfully');
        console.log('[Extension] TreeView object:', {
            visible: treeView.visible,
            hasSelection: !!treeView.selection,
            selectionLength: treeView.selection?.length
        });
        
        // Add event listeners for tree view events
        treeView.onDidExpandElement((event) => {
            console.log('TreeView element expanded:', {
                elementId: event.element.id,
                elementLabel: event.element.label,
                elementType: event.element.constructor.name
            });
        });
        
        treeView.onDidCollapseElement((event) => {
            console.log('TreeView element collapsed:', {
                elementId: event.element.id,
                elementLabel: event.element.label,
                elementType: event.element.constructor.name
            });
        });
        
        treeView.onDidChangeSelection((event) => {
            console.log('TreeView selection changed:', {
                selectedElements: event.selection.map(e => ({
                    id: e.id,
                    label: e.label,
                    type: e.constructor.name
                }))
            });
        });
        
    } catch (error) {
        console.error('Error registering TreeView:', error);
        vscode.window.showErrorMessage(`Failed to register TreeView: ${error}`);
    }

    // Register tree view commands
    const addConfigurationCommand = vscode.commands.registerCommand('keeper.tree.addConfiguration', async () => {
        await addNewConfiguration();
    });

    const authenticateCommand = vscode.commands.registerCommand('keeper.tree.authenticate', async (configId?: string) => {
        if (configId) {
            await authenticateConfiguration(configId);
        } else {
            await addNewConfiguration();
        }
    });

    const refreshConfigCommand = vscode.commands.registerCommand('keeper.tree.refresh', async (configId?: string) => {
        if (configId) {
            await refreshConfiguration(configId);
        } else {
            secretsTreeProvider.refresh();
        }
    });

    const removeConfigCommand = vscode.commands.registerCommand('keeper.tree.removeConfiguration', async (configId?: string) => {
        if (configId) {
            await removeConfiguration(configId);
        }
    });

    const setActiveConfigCommand = vscode.commands.registerCommand('keeper.tree.setActiveConfiguration', async (configId?: string) => {
        if (configId) {
            await configurationManager.setActiveConfiguration(configId);
            vscode.window.showInformationMessage('Active configuration changed');
        }
    });

    const copySecretCommand = vscode.commands.registerCommand('keeper.tree.copySecret', async (treeItem: any) => {
        // Show immediate feedback
        vscode.window.showInformationMessage(`[DEBUG] Copy command triggered for: ${treeItem?.label || 'unknown'}`);
        outputChannel.appendLine(`[COMMAND] keeper.tree.copySecret called`);
        outputChannel.appendLine(`[COMMAND] TreeItem: ${JSON.stringify(treeItem, null, 2)}`);
        
        // Handle copying secret from tree view
        console.log('Copy command called with treeItem:', {
            treeItem: treeItem,
            hasConfigId: !!treeItem?.configId,
            hasRecordId: !!treeItem?.recordId,
            hasField: !!treeItem?.field,
            treeItemType: treeItem?.constructor?.name,
            treeItemId: treeItem?.id,
            treeItemLabel: treeItem?.label,
            treeItemContextValue: treeItem?.contextValue
        });
        
        try {
            if (treeItem && treeItem.configId && treeItem.recordId && treeItem.field) {
                console.log('Calling copySecretFromTree with:', {
                    configId: treeItem.configId,
                    recordId: treeItem.recordId,
                    fieldType: treeItem.field.type
                });
                await copySecretFromTree(treeItem.configId, treeItem.recordId, treeItem.field.type);
            } else {
                console.error('Invalid tree item for copy. Missing properties:', {
                    configId: treeItem?.configId,
                    recordId: treeItem?.recordId,
                    field: treeItem?.field,
                    allProperties: Object.keys(treeItem || {})
                });
                vscode.window.showErrorMessage('Unable to copy secret: Invalid tree item');
            }
        } catch (error) {
            console.error('Error in copySecret command:', error);
            vscode.window.showErrorMessage(`Error copying secret: ${error}`);
        }
    });

    const treeGenerateCodeCommand = vscode.commands.registerCommand('keeper.tree.generateCode', async (treeItem: any) => {
        if (treeItem && treeItem.configId && treeItem.recordId && treeItem.field) {
            await codeGenerationService.showCodeGenerationPicker();
        }
    });

    const addToFavoritesCommand = vscode.commands.registerCommand('keeper.tree.addToFavorites', async (treeItem: any) => {
        if (treeItem && treeItem.configId && treeItem.recordId && treeItem.field) {
            // Get the record to get the title
            const config = configurationManager.getConfiguration(treeItem.configId);
            if (!config || !config.records) {
                vscode.window.showErrorMessage('Configuration not found or not authenticated');
                return;
            }

            const record = config.records.find(r => r.recordUid === treeItem.recordId);
            if (!record) {
                vscode.window.showErrorMessage('Record not found');
                return;
            }

            const displayName = `${record.data.title || record.recordUid} - ${treeItem.field.label || treeItem.field.type}`;
            
            try {
                // Add to favorites using QuickAccessService
                await quickAccessService.addToFavorites(treeItem.recordId, treeItem.field.label || treeItem.field.type, displayName);
                vscode.window.showInformationMessage(`Added "${displayName}" to favorites`);
            } catch (error) {
                vscode.window.showErrorMessage(`Failed to add to favorites: ${error instanceof Error ? error.message : 'Unknown error'}`);
            }
        }
    });

    const showExamplesCommand = vscode.commands.registerCommand('keeper.tree.showExamples', async (treeItem: any) => {
        if (treeItem && treeItem.configId && treeItem.recordId && treeItem.field) {
            await showSDKExamples(treeItem.recordId, treeItem.field.label || treeItem.field.type);
        }
    });

    const showRawDataCommand = vscode.commands.registerCommand('keeper.tree.showRawData', async (treeItem: any) => {
        if (treeItem && treeItem.configId && treeItem.record) {
            await showRawRecordData(treeItem.configId, treeItem.record.uid || treeItem.record.recordUid);
        }
    });

    const copyRecordUidCommand = vscode.commands.registerCommand('keeper.tree.copyRecordUid', async (treeItem: any) => {
        if (treeItem && treeItem.record) {
            const recordUid = treeItem.record.uid || treeItem.record.recordUid;
            await vscode.env.clipboard.writeText(recordUid);
            vscode.window.showInformationMessage(`Copied record UID: ${recordUid}`);
        }
    });

    const downloadFileCommand = vscode.commands.registerCommand('keeper.tree.downloadFile', async (treeItem: any) => {
        if (treeItem && treeItem.configId && treeItem.recordId && treeItem.field) {
            await downloadFileFromField(treeItem.configId, treeItem.recordId, treeItem.field);
        }
    });

    const generateEditCodeCommand = vscode.commands.registerCommand('keeper.tree.generateEditCode', async (treeItem: any) => {
        if (treeItem && treeItem.record) {
            await showRecordEditExamples(treeItem.record.uid || treeItem.record.recordUid);
        }
    });

    const generateDeleteCodeCommand = vscode.commands.registerCommand('keeper.tree.generateDeleteCode', async (treeItem: any) => {
        if (treeItem && treeItem.record) {
            await showRecordDeleteExamples(treeItem.record.uid || treeItem.record.recordUid);
        }
    });

    const generateCreateCodeCommand = vscode.commands.registerCommand('keeper.tree.generateCreateCode', async (treeItem: any) => {
        if (treeItem && treeItem.record) {
            await showRecordCreateExamples();
        }
    });

    // Legacy commands for backward compatibility
    const legacyAuthenticateCommand = vscode.commands.registerCommand('keeper.authenticate', async () => {
        await addNewConfiguration();
    });

    const listSecretsCommand = vscode.commands.registerCommand('keeper.listSecrets', async () => {
        await secretsProvider.showSecretsList();
    });

    const refreshSecretsCommand = vscode.commands.registerCommand('keeper.refreshSecrets', async () => {
        const activeConfig = configurationManager.getActiveConfiguration();
        if (activeConfig) {
            await refreshConfiguration(activeConfig.id);
        } else {
            vscode.window.showWarningMessage('No active configuration. Please add a configuration first.');
        }
    });

    const insertSecretCommand = vscode.commands.registerCommand('keeper.insertSecret', async (treeItem?: any) => {
        if (treeItem && treeItem.record && treeItem.configId) {
            // Pre-select the record from tree context
            await insertSecretReferenceFromTree(treeItem.configId, treeItem.record);
        } else {
            await secretsProvider.insertSecretReference();
        }
    });

    const logoutCommand = vscode.commands.registerCommand('keeper.logout', async () => {
        const activeConfig = configurationManager.getActiveConfiguration();
        if (activeConfig) {
            await removeConfiguration(activeConfig.id);
        } else {
            vscode.window.showWarningMessage('No active configuration to logout from.');
        }
    });

    const syncEnvCommand = vscode.commands.registerCommand('keeper.syncEnv', async () => {
        await syncEnvironmentSecrets();
    });

    const addToEnvCommand = vscode.commands.registerCommand('keeper.addToEnv', async (treeItem?: any) => {
        if (treeItem && treeItem.record && treeItem.configId) {
            // Pre-select the record from tree context
            await addSecretToEnvFromTree(treeItem.configId, treeItem.record);
        } else {
            await addSecretToEnv();
        }
    });

    const generateEnvTemplateCommand = vscode.commands.registerCommand('keeper.generateEnvTemplate', async () => {
        await generateEnvTemplate();
    });

    const generateCodeCommand = vscode.commands.registerCommand('keeper.generateCode', async () => {
        await codeGenerationService.showCodeGenerationPicker();
    });

    const saveSecretCommand = vscode.commands.registerCommand('keeper.saveSecret', async (args) => {
        await saveSecretToVault(args);
    });

    const quickAccessCommand = vscode.commands.registerCommand('keeper.quickAccess', async () => {
        await quickAccessService.showQuickAccess();
    });

    // Register providers
    const completionProvider = vscode.languages.registerCompletionItemProvider(
        { scheme: 'file' },
        notationProvider,
        '$', '{', ':', '/'
    );

    const hoverProvider = vscode.languages.registerHoverProvider(
        { scheme: 'file' },
        notationProvider
    );

    context.subscriptions.push(
        treeView,
        addConfigurationCommand,
        authenticateCommand,
        refreshConfigCommand,
        removeConfigCommand,
        setActiveConfigCommand,
        copySecretCommand,
        treeGenerateCodeCommand,
        addToFavoritesCommand,
        showExamplesCommand,
        showRawDataCommand,
        copyRecordUidCommand,
        downloadFileCommand,
        generateEditCodeCommand,
        generateDeleteCodeCommand,
        generateCreateCodeCommand,
        legacyAuthenticateCommand,
        listSecretsCommand,
        refreshSecretsCommand,
        insertSecretCommand,
        logoutCommand,
        syncEnvCommand,
        addToEnvCommand,
        generateEnvTemplateCommand,
        generateCodeCommand,
        saveSecretCommand,
        quickAccessCommand,
        completionProvider,
        hoverProvider,
        quickAccessService,
        terminalDetectionService
    );

    // Extension is ready - users can discover the TreeView naturally
}

async function addNewConfiguration(): Promise<void> {
    try {
        // Get authentication input
        const authInput = await vscode.window.showInputBox({
            prompt: 'Enter your Keeper authentication',
            placeHolder: 'One-Time Token (US:TOKEN...) or Base64 config (eyJ...)',
            password: true,
            ignoreFocusOut: true
        });

        if (!authInput) {
            return;
        }

        // Get optional custom name
        const customName = await vscode.window.showInputBox({
            prompt: 'Enter custom name for this configuration (optional)',
            placeHolder: 'Production, Development, etc.',
            ignoreFocusOut: true
        });

        // Add configuration - let the SDK handle hostname extraction
        const configId = await configurationManager.addConfiguration(authInput, customName);
        
        // Refresh tree view
        secretsTreeProvider.refresh();
        
        vscode.window.showInformationMessage('Configuration added successfully!');
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        vscode.window.showErrorMessage(`Failed to add configuration: ${errorMessage}`);
    }
}

async function authenticateConfiguration(configId: string): Promise<void> {
    try {
        await configurationManager.authenticateConfiguration(configId);
        secretsTreeProvider.refresh();
        vscode.window.showInformationMessage('Configuration authenticated successfully!');
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        vscode.window.showErrorMessage(`Authentication failed: ${errorMessage}`);
    }
}

async function refreshConfiguration(configId: string): Promise<void> {
    try {
        await configurationManager.refreshConfiguration(configId);
        secretsTreeProvider.refresh();
        vscode.window.showInformationMessage('Configuration refreshed successfully!');
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        vscode.window.showErrorMessage(`Refresh failed: ${errorMessage}`);
    }
}

async function removeConfiguration(configId: string): Promise<void> {
    const config = configurationManager.getConfiguration(configId);
    if (!config) {
        return;
    }

    const confirm = await vscode.window.showWarningMessage(
        `Are you sure you want to remove the configuration "${config.displayName}"?`,
        { modal: true },
        'Remove',
        'Cancel'
    );

    if (confirm === 'Remove') {
        try {
            await configurationManager.removeConfiguration(configId);
            secretsTreeProvider.refresh();
            vscode.window.showInformationMessage('Configuration removed successfully!');
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            vscode.window.showErrorMessage(`Failed to remove configuration: ${errorMessage}`);
        }
    }
}

async function copySecretFromTree(configId: string, recordId: string, fieldType: string): Promise<void> {
    console.log('copySecretFromTree called with:', {
        configId: configId,
        recordId: recordId,
        fieldType: fieldType
    });
    
    try {
        const config = configurationManager.getConfiguration(configId);
        console.log('Found configuration:', {
            hasConfig: !!config,
            hasRecords: !!config?.records,
            recordsCount: config?.records?.length,
            configId: config?.id
        });
        
        if (!config || !config.records) {
            throw new Error('Configuration not found or not authenticated');
        }

        console.log('Searching for record with recordId:', recordId);
        console.log('Available record UIDs:', config.records.map(r => ({
            recordUid: r.recordUid,
            uid: r.uid,
            title: r.title
        })));
        
        // Try to find record by exact match first, then by sanitized version
        let record = config.records.find(r => r.recordUid === recordId || r.uid === recordId);
        if (!record) {
            // Try to find by matching against sanitized versions
            record = config.records.find(r => {
                const sanitizedRecordUid = (r.recordUid || r.uid || '').replace(/[^a-zA-Z0-9_-]/g, '_');
                return sanitizedRecordUid === recordId;
            });
        }
        console.log('Found record:', {
            hasRecord: !!record,
            recordTitle: record?.title,
            recordUid: record?.recordUid,
            recordUidAlt: record?.uid
        });
        
        if (!record) {
            throw new Error('Record not found');
        }

        console.log('Searching for field with type:', fieldType);
        console.log('Available fields:', record.data.fields.map((f: any) => ({
            type: f.type,
            label: f.label
        })));
        
        const field = record.data.fields.find((f: any) => f.type === fieldType || f.label === fieldType);
        console.log('Found field:', {
            hasField: !!field,
            fieldType: field?.type,
            fieldLabel: field?.label,
            hasValue: !!field?.value
        });
        
        if (!field) {
            throw new Error('Field not found');
        }

        const value = field.value && field.value.length > 0 ? field.value[0] : '';
        await vscode.env.clipboard.writeText(value);
        
        vscode.window.showInformationMessage(`Copied ${field.label || fieldType} to clipboard`);
        
        // Auto-clear clipboard after 30 seconds if enabled
        const config_settings = vscode.workspace.getConfiguration('keeper');
        if (config_settings.get<boolean>('clipboardAutoClear', true)) {
            setTimeout(async () => {
                const currentClipboard = await vscode.env.clipboard.readText();
                if (currentClipboard === value) {
                    await vscode.env.clipboard.writeText('');
                }
            }, 30000);
        }
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        vscode.window.showErrorMessage(`Failed to copy secret: ${errorMessage}`);
        console.error('Copy failed:', error);
    }
}

async function syncEnvironmentSecrets() {
    const activeConfig = configurationManager.getActiveConfiguration();
    if (!activeConfig || !activeConfig.isAuthenticated) {
        vscode.window.showWarningMessage('Please authenticate with a configuration first');
        return;
    }

    try {
        const envFiles = await envSyncService.findEnvFiles();
        const existingFiles = envFiles.filter(f => f.exists);
        
        if (existingFiles.length === 0) {
            vscode.window.showWarningMessage('No .env files found in workspace');
            return;
        }

        // Let user choose which file to sync
        const selectedFile = await vscode.window.showQuickPick(
            existingFiles.map(f => ({ label: f.name, description: f.path, file: f })),
            { placeHolder: 'Select .env file to sync' }
        );

        if (!selectedFile) return;

        // Ask for dry run
        const dryRun = await vscode.window.showQuickPick(
            ['Yes, sync now', 'No, show preview first (dry run)'],
            { placeHolder: 'Do you want to sync immediately or preview changes first?' }
        );

        if (!dryRun) return;

        const isDryRun = dryRun === 'No, show preview first (dry run)';

        // Ask for backup
        let backup = false;
        if (!isDryRun) {
            const backupChoice = await vscode.window.showQuickPick(
                ['Yes, create backup', 'No, sync without backup'],
                { placeHolder: 'Create backup before syncing?' }
            );
            backup = backupChoice === 'Yes, create backup';
        }

        const result = await envSyncService.syncEnvFile(selectedFile.file.path, isDryRun, backup);
        
        if (isDryRun) {
            const preview = result.updated.length > 0 
                ? `Would update:\n${result.updated.join('\n')}`
                : 'No changes to make';
            
            vscode.window.showInformationMessage(`Sync Preview:\n${preview}`);
        } else {
            vscode.window.showInformationMessage(
                `Synced ${result.updated.length} variables${result.errors.length > 0 ? ` (${result.errors.length} errors)` : ''}`
            );
        }

        if (result.errors.length > 0) {
            vscode.window.showErrorMessage(`Errors:\n${result.errors.join('\n')}`);
        }

    } catch (error) {
        vscode.window.showErrorMessage(`Sync failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

async function addSecretToEnv() {
    const activeConfig = configurationManager.getActiveConfiguration();
    if (!activeConfig || !activeConfig.isAuthenticated) {
        vscode.window.showWarningMessage('Please authenticate with a configuration first');
        return;
    }

    try {
        const envFiles = await envSyncService.findEnvFiles();
        
        // Let user choose which file to add to
        const selectedFile = await vscode.window.showQuickPick(
            envFiles.map(f => ({ label: f.name, description: f.exists ? 'exists' : 'will be created', file: f })),
            { placeHolder: 'Select .env file to add secret to' }
        );

        if (!selectedFile) return;

        // Get variable name
        const varName = await vscode.window.showInputBox({
            prompt: 'Enter environment variable name',
            placeHolder: 'DATABASE_URL',
            validateInput: (value) => {
                if (!value || !/^[A-Z_][A-Z0-9_]*$/.test(value)) {
                    return 'Variable name must contain only uppercase letters, numbers, and underscores';
                }
                return null;
            }
        });

        if (!varName) return;

        // Let user select secret
        const secrets = activeConfig.records || [];
        const selectedSecret = await vscode.window.showQuickPick(
            secrets.map(s => ({ label: s.data.title || s.recordUid, description: s.recordUid, secret: s })),
            { placeHolder: 'Select secret' }
        );

        if (!selectedSecret) return;

        // Let user select field
        const selectedField = await vscode.window.showQuickPick(
            selectedSecret.secret.data.fields.map((f: any) => ({ 
                label: f.label || f.type, 
                description: f.type, 
                field: f 
            })),
            { placeHolder: 'Select field' }
        ) as any;

        if (!selectedField) return;

        // Ask for template value if they want to combine with other text
        const templateValue = await vscode.window.showInputBox({
            prompt: 'Enter template value (or press Enter for simple reference)',
            placeHolder: `postgresql://user:keeper://${selectedSecret.secret.recordUid}/field/${selectedField.field.label || selectedField.field.type}@localhost:5432/db`,
            value: `keeper://${selectedSecret.secret.recordUid}/field/${selectedField.field.label || selectedField.field.type}`
        });

        if (templateValue === undefined) return;

        await envSyncService.addSecretToEnvFile(
            selectedFile.file.path, 
            varName, 
            selectedSecret.secret.recordUid, 
            selectedField.field.label || selectedField.field.type,
            templateValue
        );

    } catch (error) {
        vscode.window.showErrorMessage(`Failed to add secret: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

async function generateEnvTemplate() {
    const activeConfig = configurationManager.getActiveConfiguration();
    if (!activeConfig || !activeConfig.isAuthenticated) {
        vscode.window.showWarningMessage('Please authenticate with a configuration first');
        return;
    }

    try {
        const envFiles = await envSyncService.findEnvFiles();
        
        // Let user choose which file to generate
        const selectedFile = await vscode.window.showQuickPick(
            envFiles.map(f => ({ label: f.name, description: f.exists ? 'will be overwritten' : 'will be created', file: f })),
            { placeHolder: 'Select .env file to generate template for' }
        );

        if (!selectedFile) return;

        // TODO: Let user select multiple secrets for template generation
        vscode.window.showInformationMessage('Template generation feature coming soon!');

    } catch (error) {
        vscode.window.showErrorMessage(`Failed to generate template: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

async function saveSecretToVault(args: any) {
    const activeConfig = configurationManager.getActiveConfiguration();
    if (!activeConfig || !activeConfig.isAuthenticated) {
        vscode.window.showWarningMessage('Please authenticate with a configuration first');
        return;
    }

    try {
        const data = JSON.parse(args);
        
        // Ask for confirmation
        const confirm = await vscode.window.showWarningMessage(
            `Do you want to save this ${data.type} to Keeper Vault?`,
            { modal: true },
            'Yes, Save',
            'Cancel'
        );

        if (confirm !== 'Yes, Save') {
            return;
        }

        // Get title for the record
        const title = await vscode.window.showInputBox({
            prompt: 'Enter a title for this secret',
            value: `${data.type} - ${new Date().toISOString().split('T')[0]}`,
            validateInput: (value) => {
                if (!value || value.trim().length < 3) {
                    return 'Title must be at least 3 characters long';
                }
                return null;
            }
        });

        if (!title) return;

        // Get folder to save in
        const folders = activeConfig.folders || [];
        const selectedFolder = await vscode.window.showQuickPick(
            [
                { label: 'Root Folder', value: '' },
                ...folders.map(f => ({ label: f.name, value: f.uid }))
            ],
            { placeHolder: 'Select folder to save in' }
        );

        if (!selectedFolder) return;

        // Create the record
        const recordData = {
            title: title,
            type: 'login',
            fields: [
                {
                    type: 'login',
                    value: [data.type]
                },
                {
                    type: 'password',
                    value: [data.value]
                },
                {
                    type: 'notes',
                    value: [`Saved from VS Code\nType: ${data.type}\nDate: ${new Date().toISOString()}`]
                }
            ]
        };

        // Save to vault
        const recordUid = await configurationManager.createRecord(activeConfig.id, selectedFolder.value, recordData);

        // Ask if user wants to replace the hardcoded value with environment variable
        const replaceChoice = await vscode.window.showInformationMessage(
            'Secret saved successfully! Do you want to replace the hardcoded value with an environment variable?',
            'Yes, Replace',
            'No, Keep As Is'
        );

        if (replaceChoice === 'Yes, Replace') {
            // Get variable name
            const varName = await vscode.window.showInputBox({
                prompt: 'Enter environment variable name',
                value: data.type.toUpperCase().replace(/[^A-Z0-9]/g, '_') + '_SECRET',
                validateInput: (value) => {
                    if (!value || !/^[A-Z_][A-Z0-9_]*$/.test(value)) {
                        return 'Variable name must contain only uppercase letters, numbers, and underscores';
                    }
                    return null;
                }
            });

            if (varName) {
                // Replace the hardcoded value with environment variable
                const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(data.document));
                const edit = new vscode.WorkspaceEdit();
                const range = new vscode.Range(
                    data.range.start.line, data.range.start.character,
                    data.range.end.line, data.range.end.character
                );
                
                edit.replace(document.uri, range, `process.env.${varName}`);
                await vscode.workspace.applyEdit(edit);

                // Add to .env file
                await envSyncService.addSecretToEnvFile(
                    '.env',
                    varName,
                    recordUid,
                    'password',
                    `keeper://${recordUid}/field/password`
                );

                vscode.window.showInformationMessage(
                    `Secret saved and replaced with ${varName}! Added to .env file with keeper reference.`
                );
            }
        } else {
            vscode.window.showInformationMessage('Secret saved to Keeper Vault successfully!');
        }

    } catch (error) {
        vscode.window.showErrorMessage(`Failed to save secret: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

async function showSDKExamples(recordId: string, fieldName: string): Promise<void> {
    const notation = `keeper://${recordId}/field/${fieldName}`;
    
    const examples = `
# Keeper SDK Examples - Retrieving Field "${fieldName}"

## JavaScript/Node.js
\`\`\`javascript
const { getSecrets } = require('@keeper-security/secrets-manager-core');

// Get all secrets
const secrets = await getSecrets(options);

// Find specific record
const record = secrets.records.find(r => r.recordUid === '${recordId}');

// Get field value
const fieldValue = record.data.fields.find(f => f.label === '${fieldName}' || f.type === '${fieldName}')?.value?.[0];

// Or use notation directly
const value = await getValue(options, '${notation}');
\`\`\`

## Python
\`\`\`python
from keeper_secrets_manager_core import SecretsManager

# Initialize
secrets_manager = SecretsManager(config=config)

# Get all secrets
secrets = secrets_manager.get_secrets()

# Find specific record
record = next((r for r in secrets.records if r.record_uid == '${recordId}'), None)

# Get field value
field_value = next((f.value[0] for f in record.dict.get('fields', []) 
                   if f.label == '${fieldName}' or f.type == '${fieldName}'), None)

# Or use notation directly
value = secrets_manager.get_value('${notation}')
\`\`\`

## Go
\`\`\`go
package main

import (
    "github.com/keeper-security/secrets-manager-go/core"
)

// Get all secrets
secrets, err := core.GetSecrets(options)

// Find specific record
var record *core.Record
for _, r := range secrets.Records {
    if r.RecordUid == "${recordId}" {
        record = r
        break
    }
}

// Get field value
var fieldValue string
for _, field := range record.Data.Fields {
    if field.Label == "${fieldName}" || field.Type == "${fieldName}" {
        if len(field.Value) > 0 {
            fieldValue = field.Value[0]
        }
        break
    }
}

// Or use notation directly
value, err := core.GetValue(options, "${notation}")
\`\`\`

## Java
\`\`\`java
import com.keepersecurity.secretsManager.core.SecretsManager;
import com.keepersecurity.secretsManager.core.KeeperSecrets;

// Get all secrets
KeeperSecrets secrets = SecretsManager.getSecrets(options);

// Find specific record
KeeperRecord record = secrets.getRecords().stream()
    .filter(r -> "${recordId}".equals(r.getRecordUid()))
    .findFirst()
    .orElse(null);

// Get field value
String fieldValue = record.getData().getFields().stream()
    .filter(f -> "${fieldName}".equals(f.getLabel()) || "${fieldName}".equals(f.getType()))
    .map(f -> f.getValue().length > 0 ? f.getValue()[0] : null)
    .findFirst()
    .orElse(null);

// Or use notation directly
String value = SecretsManager.getValue(options, "${notation}");
\`\`\`

## .NET
\`\`\`csharp
using SecretsManager;

// Get all secrets
var secrets = await SecretsManagerClient.GetSecrets(options);

// Find specific record
var record = secrets.Records
    .FirstOrDefault(r => r.RecordUid == "${recordId}");

// Get field value
var fieldValue = record?.Data?.Fields
    ?.FirstOrDefault(f => f.Label == "${fieldName}" || f.Type == "${fieldName}")
    ?.Value?.FirstOrDefault();

// Or use notation directly
var value = await SecretsManagerClient.GetValue(options, "${notation}");
\`\`\`

## CLI
\`\`\`bash
# Get specific field value
keeper secret get --uid ${recordId} --field "${fieldName}"

# Or use notation
keeper secret get --notation "${notation}"
\`\`\`
`;

    const doc = await vscode.workspace.openTextDocument({
        content: examples,
        language: 'markdown'
    });
    await vscode.window.showTextDocument(doc);
}

async function showRawRecordData(configId: string, recordId: string): Promise<void> {
    try {
        const config = configurationManager.getConfiguration(configId);
        if (!config || !config.records) {
            throw new Error('Configuration not found or not authenticated');
        }

        const record = config.records.find(r => r.recordUid === recordId);
        if (!record) {
            throw new Error('Record not found');
        }

        const rawData = JSON.stringify(record, null, 2);
        
        const doc = await vscode.workspace.openTextDocument({
            content: rawData,
            language: 'json'
        });
        await vscode.window.showTextDocument(doc);
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        vscode.window.showErrorMessage(`Failed to show raw data: ${errorMessage}`);
    }
}

async function addSecretToEnvFromTree(configId: string, record: any): Promise<void> {
    try {
        const config = configurationManager.getConfiguration(configId);
        if (!config || !config.records) {
            vscode.window.showErrorMessage('Configuration not found or not authenticated');
            return;
        }

        const envFiles = await envSyncService.findEnvFiles();
        
        // Let user choose which file to add to
        const selectedFile = await vscode.window.showQuickPick(
            envFiles.map(f => ({ label: f.name, description: f.exists ? 'exists' : 'will be created', file: f })),
            { placeHolder: 'Select .env file to add secret to' }
        );

        if (!selectedFile) return;

        // Get variable name
        const varName = await vscode.window.showInputBox({
            prompt: 'Enter environment variable name',
            placeHolder: 'DATABASE_URL',
            validateInput: (value) => {
                if (!value || !/^[A-Z_][A-Z0-9_]*$/.test(value)) {
                    return 'Variable name must contain only uppercase letters, numbers, and underscores';
                }
                return null;
            }
        });

        if (!varName) return;

        // Let user select field
        const selectedField = await vscode.window.showQuickPick(
            record.data.fields.map((f: any) => ({ 
                label: f.label || f.type, 
                description: f.type, 
                field: f 
            })),
            { placeHolder: 'Select field' }
        ) as any;

        if (!selectedField) return;

        // Ask for template value if they want to combine with other text
        const templateValue = await vscode.window.showInputBox({
            prompt: 'Enter template value (or press Enter for simple reference)',
            placeHolder: `postgresql://user:keeper://${record.recordUid}/field/${selectedField.field.label || selectedField.field.type}@localhost:5432/db`,
            value: `keeper://${record.recordUid}/field/${selectedField.field.label || selectedField.field.type}`
        });

        if (templateValue === undefined) return;

        await envSyncService.addSecretToEnvFile(
            selectedFile.file.path, 
            varName, 
            record.recordUid, 
            selectedField.field.label || selectedField.field.type,
            templateValue
        );

        vscode.window.showInformationMessage(`Added ${varName} to ${selectedFile.file.name}`);

    } catch (error) {
        vscode.window.showErrorMessage(`Failed to add secret: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

async function insertSecretReferenceFromTree(configId: string, record: any): Promise<void> {
    try {
        const config = configurationManager.getConfiguration(configId);
        if (!config || !config.records) {
            vscode.window.showErrorMessage('Configuration not found or not authenticated');
            return;
        }

        // Let user select field
        const selectedField = await vscode.window.showQuickPick(
            record.data.fields.map((f: any) => ({ 
                label: f.label || f.type, 
                description: f.type, 
                field: f 
            })),
            { placeHolder: 'Select field to insert reference for' }
        ) as any;

        if (!selectedField) return;

        const notation = `\${keeper://${record.recordUid}/field/${selectedField.field.label || selectedField.field.type}}`;
        const editor = vscode.window.activeTextEditor;
        
        if (editor) {
            await editor.edit(editBuilder => {
                editBuilder.insert(editor.selection.active, notation);
            });
            vscode.window.showInformationMessage('Reference inserted into editor');
        } else {
            await vscode.env.clipboard.writeText(notation);
            vscode.window.showInformationMessage('Reference copied to clipboard (no active editor)');
        }

    } catch (error) {
        vscode.window.showErrorMessage(`Failed to insert reference: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

async function downloadFileFromField(configId: string, recordId: string, field: any): Promise<void> {
    try {
        const config = configurationManager.getConfiguration(configId);
        if (!config || !config.records) {
            throw new Error('Configuration not found or not authenticated');
        }

        const record = config.records.find(r => r.recordUid === recordId);
        if (!record) {
            throw new Error('Record not found');
        }

        // Check if field is a file type
        if (field.type !== 'file') {
            vscode.window.showErrorMessage('Selected field is not a file');
            return;
        }

        // Get file data - this would need to be implemented in the KSM SDK
        // For now, show a placeholder implementation
        const fileName = field.label || `file_${recordId}`;
        const fileData = field.value && field.value.length > 0 ? field.value[0] : null;
        
        if (!fileData) {
            vscode.window.showErrorMessage('No file data available');
            return;
        }

        // Ask user where to save the file
        const uri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(fileName),
            saveLabel: 'Download File'
        });

        if (!uri) return;

        // Convert base64 data to buffer and save
        try {
            const buffer = Buffer.from(fileData, 'base64');
            await vscode.workspace.fs.writeFile(uri, buffer);
            vscode.window.showInformationMessage(`File downloaded to ${uri.fsPath}`);
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to save file: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }

    } catch (error) {
        vscode.window.showErrorMessage(`Failed to download file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

async function selectLanguageForCodeGeneration(): Promise<string | undefined> {
    const languages = [
        { label: 'JavaScript/Node.js', value: 'javascript' },
        { label: 'Python', value: 'python' },
        { label: 'Go', value: 'go' },
        { label: 'Java', value: 'java' },
        { label: '.NET/C#', value: 'csharp' },
        { label: 'CLI/Bash', value: 'cli' },
        { label: 'All Languages', value: 'all' }
    ];

    const selected = await vscode.window.showQuickPick(languages, {
        placeHolder: 'Select programming language for code examples'
    });

    return selected?.value;
}

function generateJavaScriptEditExample(recordUid: string): string {
    return `
## JavaScript/Node.js
\`\`\`javascript
const { getSecrets, updateSecret } = require('@keeper-security/secrets-manager-core');

// Get the specific record by UID
const { records } = await getSecrets(options, ['${recordUid}']);
const record = records[0];

// Update the password field
const passwordField = record.data.fields.find(f => f.type === 'password');
if (passwordField) {
    passwordField.value[0] = 'new_password_value';
}

// Update the title
record.data.title = 'Updated Title';

// Save the changes
await updateSecret(options, record);
\`\`\``;
}

function generatePythonEditExample(recordUid: string): string {
    return `
## Python
\`\`\`python
from keeper_secrets_manager_core import SecretsManager

# Initialize
secrets_manager = SecretsManager(config=config)

# Get the specific record by UID
records = secrets_manager.get_secrets(['${recordUid}'])
record = records[0]

# Update the password field directly
record.password = 'new_password_value'

# Update the title
record.title = 'Updated Title'

# Save the changes
secrets_manager.save(record)
\`\`\``;
}

function generateGoEditExample(recordUid: string): string {
    return `
## Go
\`\`\`go
package main

import (
    "github.com/keeper-security/secrets-manager-go/core"
)

// Get the record to edit
secrets, err := core.GetSecrets(options)
if err != nil {
    log.Fatal(err)
}

var record *core.Record
for _, r := range secrets.Records {
    if r.RecordUid == "${recordUid}" {
        record = r
        break
    }
}

// Modify the record data
updatedRecord := &core.RecordData{
    Title: "Updated Title",
    Type:  record.Data.Type,
    Fields: []*core.Field{},
}

// Keep existing fields except password
for _, field := range record.Data.Fields {
    if field.Type != "password" {
        updatedRecord.Fields = append(updatedRecord.Fields, field)
    }
}

// Add new password field
updatedRecord.Fields = append(updatedRecord.Fields, &core.Field{
    Type:  "password",
    Value: []string{"new_password_value"},
})

// Update the record
err = core.UpdateSecret(options, "${recordUid}", updatedRecord)
\`\`\``;
}

function generateJavaEditExample(recordUid: string): string {
    return `
## Java
\`\`\`java
import com.keepersecurity.secretsManager.core.SecretsManager;
import com.keepersecurity.secretsManager.core.KeeperSecrets;

// Get the record to edit
KeeperSecrets secrets = SecretsManager.getSecrets(options);
KeeperRecord record = secrets.getRecords().stream()
    .filter(r -> "${recordUid}".equals(r.getRecordUid()))
    .findFirst()
    .orElse(null);

// Create updated record data
Map<String, Object> updatedRecord = new HashMap<>();
updatedRecord.put("title", "Updated Title");
updatedRecord.put("type", record.getData().get("type"));

// Keep existing fields except password, add new password
List<Map<String, Object>> fields = new ArrayList<>();
for (Map<String, Object> field : (List<Map<String, Object>>) record.getData().get("fields")) {
    if (!"password".equals(field.get("type"))) {
        fields.add(field);
    }
}

Map<String, Object> passwordField = new HashMap<>();
passwordField.put("type", "password");
passwordField.put("value", Arrays.asList("new_password_value"));
fields.add(passwordField);

updatedRecord.put("fields", fields);

// Update the record
SecretsManager.updateSecret(options, "${recordUid}", updatedRecord);
\`\`\``;
}

function generateCSharpEditExample(recordUid: string): string {
    return `
## .NET/C#
\`\`\`csharp
using SecretsManager;

// Get the record to edit
var secrets = await SecretsManagerClient.GetSecrets(options);
var record = secrets.Records
    .FirstOrDefault(r => r.RecordUid == "${recordUid}");

// Modify the record data
var updatedRecord = new Dictionary<string, object>
{
    ["title"] = "Updated Title",
    ["type"] = record.Data["type"],
    ["fields"] = record.Data["fields"]
        .Cast<Dictionary<string, object>>()
        .Where(f => f["type"].ToString() != "password")
        .Concat(new[] {
            new Dictionary<string, object>
            {
                ["type"] = "password",
                ["value"] = new[] { "new_password_value" }
            }
        })
        .ToList()
};

// Update the record
await SecretsManagerClient.UpdateSecret(options, "${recordUid}", updatedRecord);
\`\`\``;
}

function generateCliEditExample(recordUid: string): string {
    return `
## CLI/Bash
\`\`\`bash
# Edit record interactively
keeper record edit --uid ${recordUid}

# Or update specific fields
keeper record update --uid ${recordUid} --field password --value "new_password_value"

# Update title
keeper record update --uid ${recordUid} --title "Updated Title"
\`\`\``;
}

async function showRecordEditExamples(recordUid: string): Promise<void> {
    const language = await selectLanguageForCodeGeneration();
    if (!language) return;

    let examples = `# Keeper SDK Examples - Edit Record "${recordUid}"`;

    if (language === 'all') {
        examples += generateJavaScriptEditExample(recordUid);
        examples += generatePythonEditExample(recordUid);
        examples += generateGoEditExample(recordUid);
        examples += generateJavaEditExample(recordUid);
        examples += generateCSharpEditExample(recordUid);
        examples += generateCliEditExample(recordUid);
    } else {
        switch (language) {
            case 'javascript':
                examples += generateJavaScriptEditExample(recordUid);
                break;
            case 'python':
                examples += generatePythonEditExample(recordUid);
                break;
            case 'go':
                examples += generateGoEditExample(recordUid);
                break;
            case 'java':
                examples += generateJavaEditExample(recordUid);
                break;
            case 'csharp':
                examples += generateCSharpEditExample(recordUid);
                break;
            case 'cli':
                examples += generateCliEditExample(recordUid);
                break;
        }
    }


    const doc = await vscode.workspace.openTextDocument({
        content: examples,
        language: 'markdown'
    });
    await vscode.window.showTextDocument(doc);
}

async function showRecordDeleteExamples(recordUid: string): Promise<void> {
    const language = await selectLanguageForCodeGeneration();
    if (!language) return;

    let examples = `# Keeper SDK Examples - Delete Record "${recordUid}"

⚠️ **Warning**: This operation permanently deletes the record. Always backup important data first.
`;

    if (language === 'all') {
        examples += `
## JavaScript/Node.js
\`\`\`javascript
const { deleteSecret } = require('@keeper-security/secrets-manager-core');

// Delete the record
await deleteSecret(options, '${recordUid}');
console.log('Record deleted successfully');
\`\`\`

## Python
\`\`\`python
from keeper_secrets_manager_core import SecretsManager

# Initialize
secrets_manager = SecretsManager(config=config)

# Delete the record
secrets_manager.delete_secret('${recordUid}')
print('Record deleted successfully')
\`\`\`

## Go
\`\`\`go
package main

import (
    "fmt"
    "github.com/keeper-security/secrets-manager-go/core"
)

// Delete the record
err := core.DeleteSecret(options, "${recordUid}")
if err != nil {
    log.Fatal(err)
}

fmt.Println("Record deleted successfully")
\`\`\`

## Java
\`\`\`java
import com.keepersecurity.secretsManager.core.SecretsManager;

// Delete the record
SecretsManager.deleteSecret(options, "${recordUid}");
System.out.println("Record deleted successfully");
\`\`\`

## .NET/C#
\`\`\`csharp
using SecretsManager;

// Delete the record
await SecretsManagerClient.DeleteSecret(options, "${recordUid}");
Console.WriteLine("Record deleted successfully");
\`\`\`

## CLI/Bash
\`\`\`bash
# Delete record (with confirmation)
keeper record delete --uid ${recordUid}

# Force delete without confirmation
keeper record delete --uid ${recordUid} --force
\`\`\``;
    } else {
        switch (language) {
            case 'javascript':
                examples += `
## JavaScript/Node.js
\`\`\`javascript
const { getSecrets, deleteSecret } = require('@keeper-security/secrets-manager-core');

// Get the specific record by UID first (optional verification)
const { records } = await getSecrets(options, ['${recordUid}']);
if (records.length === 0) {
    console.log('Record not found');
    return;
}

// Delete the record
await deleteSecret(options, '${recordUid}');
console.log('Record deleted successfully');
\`\`\``;
                break;
            case 'python':
                examples += `
## Python
\`\`\`python
from keeper_secrets_manager_core import SecretsManager

# Initialize
secrets_manager = SecretsManager(config=config)

# Get the record first (optional verification)
records = secrets_manager.get_secrets(['${recordUid}'])
if not records:
    print('Record not found')
    return

# Delete the record
record = records[0]
secrets_manager.delete_secret(record)
print('Record deleted successfully')
\`\`\``;
                break;
            case 'go':
                examples += `
## Go
\`\`\`go
package main

import (
    "fmt"
    "github.com/keeper-security/secrets-manager-go/core"
)

// Delete the record
err := core.DeleteSecret(options, "${recordUid}")
if err != nil {
    log.Fatal(err)
}

fmt.Println("Record deleted successfully")
\`\`\``;
                break;
            case 'java':
                examples += `
## Java
\`\`\`java
import com.keepersecurity.secretsManager.core.SecretsManager;

// Delete the record
SecretsManager.deleteSecret(options, "${recordUid}");
System.out.println("Record deleted successfully");
\`\`\``;
                break;
            case 'csharp':
                examples += `
## .NET/C#
\`\`\`csharp
using SecretsManager;

// Delete the record
await SecretsManagerClient.DeleteSecret(options, "${recordUid}");
Console.WriteLine("Record deleted successfully");
\`\`\``;
                break;
            case 'cli':
                examples += `
## CLI/Bash
\`\`\`bash
# Delete record (with confirmation)
keeper record delete --uid ${recordUid}

# Force delete without confirmation
keeper record delete --uid ${recordUid} --force
\`\`\``;
                break;
        }
    }

    const doc = await vscode.workspace.openTextDocument({
        content: examples,
        language: 'markdown'
    });
    await vscode.window.showTextDocument(doc);
}

async function showRecordCreateExamples(): Promise<void> {
    const language = await selectLanguageForCodeGeneration();
    if (!language) return;

    let examples = `# Keeper SDK Examples - Create New Record

💡 **Tip**: This creates a new record in your Keeper vault with custom fields.
`;

    if (language === 'all') {
        examples += `
## JavaScript/Node.js
\`\`\`javascript
const { createSecret } = require('@keeper-security/secrets-manager-core');

// Define the new record
const newRecord = {
    title: 'My New Login',
    type: 'login',
    fields: [
        {
            type: 'login',
            value: ['username@example.com']
        },
        {
            type: 'password',
            value: ['secure_password_123']
        },
        {
            type: 'url',
            value: ['https://example.com']
        },
        {
            type: 'notes',
            value: ['Created via VS Code extension']
        }
    ]
};

// Create the record (in root folder)
const recordUid = await createSecret(options, '', newRecord);
console.log('Record created with UID:', recordUid);
\`\`\`

## Python
\`\`\`python
from keeper_secrets_manager_core import SecretsManager

# Initialize
secrets_manager = SecretsManager(config=config)

# Define the new record
new_record = {
    'title': 'My New Login',
    'type': 'login',
    'fields': [
        {
            'type': 'login',
            'value': ['username@example.com']
        },
        {
            'type': 'password',
            'value': ['secure_password_123']
        },
        {
            'type': 'url',
            'value': ['https://example.com']
        },
        {
            'type': 'notes',
            'value': ['Created via VS Code extension']
        }
    ]
}

# Create the record (in root folder)
record_uid = secrets_manager.create_secret('', new_record)
print(f'Record created with UID: {record_uid}')
\`\`\`

## Go
\`\`\`go
package main

import (
    "fmt"
    "github.com/keeper-security/secrets-manager-go/core"
)

// Define the new record
newRecord := &core.RecordData{
    Title: "My New Login",
    Type:  "login",
    Fields: []*core.Field{
        {
            Type:  "login",
            Value: []string{"username@example.com"},
        },
        {
            Type:  "password",
            Value: []string{"secure_password_123"},
        },
        {
            Type:  "url",
            Value: []string{"https://example.com"},
        },
        {
            Type:  "notes",
            Value: []string{"Created via VS Code extension"},
        },
    },
}

// Create the record (in root folder)
recordUid, err := core.CreateSecret(options, "", newRecord)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Record created with UID: %s\\n", recordUid)
\`\`\`

## Java
\`\`\`java
import com.keepersecurity.secretsManager.core.SecretsManager;
import java.util.*;

// Define the new record
Map<String, Object> newRecord = new HashMap<>();
newRecord.put("title", "My New Login");
newRecord.put("type", "login");

List<Map<String, Object>> fields = new ArrayList<>();

Map<String, Object> loginField = new HashMap<>();
loginField.put("type", "login");
loginField.put("value", Arrays.asList("username@example.com"));
fields.add(loginField);

Map<String, Object> passwordField = new HashMap<>();
passwordField.put("type", "password");
passwordField.put("value", Arrays.asList("secure_password_123"));
fields.add(passwordField);

Map<String, Object> urlField = new HashMap<>();
urlField.put("type", "url");
urlField.put("value", Arrays.asList("https://example.com"));
fields.add(urlField);

Map<String, Object> notesField = new HashMap<>();
notesField.put("type", "notes");
notesField.put("value", Arrays.asList("Created via VS Code extension"));
fields.add(notesField);

newRecord.put("fields", fields);

// Create the record (in root folder)
String recordUid = SecretsManager.createSecret(options, "", newRecord);
System.out.println("Record created with UID: " + recordUid);
\`\`\`

## .NET/C#
\`\`\`csharp
using SecretsManager;

// Define the new record
var newRecord = new Dictionary<string, object>
{
    ["title"] = "My New Login",
    ["type"] = "login",
    ["fields"] = new List<Dictionary<string, object>>
    {
        new Dictionary<string, object>
        {
            ["type"] = "login",
            ["value"] = new[] { "username@example.com" }
        },
        new Dictionary<string, object>
        {
            ["type"] = "password",
            ["value"] = new[] { "secure_password_123" }
        },
        new Dictionary<string, object>
        {
            ["type"] = "url",
            ["value"] = new[] { "https://example.com" }
        },
        new Dictionary<string, object>
        {
            ["type"] = "notes",
            ["value"] = new[] { "Created via VS Code extension" }
        }
    }
};

// Create the record (in root folder)
var recordUid = await SecretsManagerClient.CreateSecret(options, "", newRecord);
Console.WriteLine($"Record created with UID: {recordUid}");
\`\`\`

## CLI/Bash
\`\`\`bash
# Create a new login record
keeper record create \\
    --title "My New Login" \\
    --type login \\
    --field "login=username@example.com" \\
    --field "password=secure_password_123" \\
    --field "url=https://example.com" \\
    --field "notes=Created via VS Code extension"

# Create in specific folder
keeper record create \\
    --folder-uid FOLDER_UID \\
    --title "Database Credentials" \\
    --type database \\
    --field "host=db.example.com" \\
    --field "login=admin" \\
    --field "password=secret123"
\`\`\``;
    } else {
        switch (language) {
            case 'javascript':
                examples += `
## JavaScript/Node.js
\`\`\`javascript
const { createSecret } = require('@keeper-security/secrets-manager-core');

// Define the new record data
const recordData = {
    title: 'My New Login',
    type: 'login',
    fields: [
        {
            type: 'login',
            value: ['username@example.com']
        },
        {
            type: 'password', 
            value: ['secure_password_123']
        },
        {
            type: 'url',
            value: ['https://example.com']
        }
    ],
    notes: 'Created via VS Code extension'
};

// Create the record in a specific folder (use '' for root)
const folderUid = 'YOUR_FOLDER_UID'; // Replace with actual folder UID
const recordUid = await createSecret(options, folderUid, recordData);
console.log('Record created with UID:', recordUid);
\`\`\``;
                break;
            case 'python':
                examples += `
## Python
\`\`\`python
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.dto.dtos import RecordCreate, RecordField

# Initialize
secrets_manager = SecretsManager(config=config)

# Create the new record structure
new_record = RecordCreate(
    record_type='login',
    title='My New Login'
)

# Add fields
new_record.fields = [
    RecordField(field_type='login', value=['username@example.com']),
    RecordField(field_type='password', value=['secure_password_123']),
    RecordField(field_type='url', value=['https://example.com'])
]

# Add notes
new_record.notes = 'Created via VS Code extension'

# Create the record in a specific folder (use '' for root)
folder_uid = 'YOUR_FOLDER_UID'  # Replace with actual folder UID
record_uid = secrets_manager.create_secret(folder_uid, new_record)
print(f'Record created with UID: {record_uid}')
\`\`\``;
                break;
            case 'go':
                examples += `
## Go
\`\`\`go
package main

import (
    "fmt"
    "github.com/keeper-security/secrets-manager-go/core"
)

// Define the new record
newRecord := &core.RecordData{
    Title: "My New Login",
    Type:  "login",
    Fields: []*core.Field{
        {
            Type:  "login",
            Value: []string{"username@example.com"},
        },
        {
            Type:  "password",
            Value: []string{"secure_password_123"},
        },
        {
            Type:  "url",
            Value: []string{"https://example.com"},
        },
        {
            Type:  "notes",
            Value: []string{"Created via VS Code extension"},
        },
    },
}

// Create the record (in root folder)
recordUid, err := core.CreateSecret(options, "", newRecord)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Record created with UID: %s\\n", recordUid)
\`\`\``;
                break;
            case 'java':
                examples += `
## Java
\`\`\`java
import com.keepersecurity.secretsManager.core.SecretsManager;
import java.util.*;

// Define the new record
Map<String, Object> newRecord = new HashMap<>();
newRecord.put("title", "My New Login");
newRecord.put("type", "login");

List<Map<String, Object>> fields = new ArrayList<>();

Map<String, Object> loginField = new HashMap<>();
loginField.put("type", "login");
loginField.put("value", Arrays.asList("username@example.com"));
fields.add(loginField);

Map<String, Object> passwordField = new HashMap<>();
passwordField.put("type", "password");
passwordField.put("value", Arrays.asList("secure_password_123"));
fields.add(passwordField);

newRecord.put("fields", fields);

// Create the record (in root folder)
String recordUid = SecretsManager.createSecret(options, "", newRecord);
System.out.println("Record created with UID: " + recordUid);
\`\`\``;
                break;
            case 'csharp':
                examples += `
## .NET/C#
\`\`\`csharp
using SecretsManager;

// Define the new record
var newRecord = new Dictionary<string, object>
{
    ["title"] = "My New Login",
    ["type"] = "login",
    ["fields"] = new List<Dictionary<string, object>>
    {
        new Dictionary<string, object>
        {
            ["type"] = "login",
            ["value"] = new[] { "username@example.com" }
        },
        new Dictionary<string, object>
        {
            ["type"] = "password",
            ["value"] = new[] { "secure_password_123" }
        }
    }
};

// Create the record (in root folder)
var recordUid = await SecretsManagerClient.CreateSecret(options, "", newRecord);
Console.WriteLine($"Record created with UID: {recordUid}");
\`\`\``;
                break;
            case 'cli':
                examples += `
## CLI/Bash
\`\`\`bash
# Create a new login record
keeper record create \\
    --title "My New Login" \\
    --type login \\
    --field "login=username@example.com" \\
    --field "password=secure_password_123" \\
    --field "url=https://example.com"

# Create in specific folder
keeper record create \\
    --folder-uid FOLDER_UID \\
    --title "Database Credentials" \\
    --type database \\
    --field "host=db.example.com" \\
    --field "login=admin" \\
    --field "password=secret123"
\`\`\``;
                break;
        }
    }

    const doc = await vscode.workspace.openTextDocument({
        content: examples,
        language: 'markdown'
    });
    await vscode.window.showTextDocument(doc);
}

export function deactivate() {
    console.log('Keeper Secrets Manager extension is now deactivated!');
}