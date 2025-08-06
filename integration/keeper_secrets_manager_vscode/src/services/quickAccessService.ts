import * as vscode from 'vscode';
import { KSMService } from './ksmService';
import { SettingsService } from './settingsService';

export interface FavoriteSecret {
    recordUid: string;
    fieldName: string;
    displayName: string;
    lastUsed: number;
}

export class QuickAccessService {
    private static readonly FAVORITES_KEY = 'keeper.favorites';
    private static readonly RECENT_KEY = 'keeper.recent';
    private clipboard: vscode.Clipboard;
    private clipboardTimeout: NodeJS.Timeout | undefined;

    constructor(
        private ksmService: KSMService,
        private context: vscode.ExtensionContext,
        private settingsService?: SettingsService
    ) {
        this.clipboard = vscode.env.clipboard;
    }

    public async showQuickAccess(): Promise<void> {
        if (!this.ksmService.isAuthenticated()) {
            const action = await vscode.window.showWarningMessage(
                'Please authenticate with Keeper first',
                'Authenticate'
            );
            if (action === 'Authenticate') {
                await vscode.commands.executeCommand('keeper.authenticate');
            }
            return;
        }

        const options = [
            {
                label: '$(search) Search All Secrets',
                description: 'Search and copy from all secrets',
                action: 'search'
            },
            {
                label: '$(star) Quick Copy Favorites',
                description: 'Copy from favorite secrets',
                action: 'favorites'
            },
            {
                label: '$(history) Recent Secrets',
                description: 'Copy from recently used secrets',
                action: 'recent'
            },
            {
                label: '$(settings-gear) Manage Favorites',
                description: 'Add or remove favorite secrets',
                action: 'manage'
            }
        ];

        const selected = await vscode.window.showQuickPick(options, {
            placeHolder: 'Quick Secret Launcher - Choose option'
        });

        if (!selected) return;

        switch (selected.action) {
            case 'search':
                await this.searchAndCopySecret();
                break;
            case 'favorites':
                await this.copyFromFavorites();
                break;
            case 'recent':
                await this.copyFromRecent();
                break;
            case 'manage':
                await this.manageFavorites();
                break;
        }
    }

    private async searchAndCopySecret(): Promise<void> {
        const secrets = this.ksmService.getSecrets();
        
        if (secrets.length === 0) {
            vscode.window.showInformationMessage('No secrets found');
            return;
        }

        // Create searchable items
        const items = secrets.flatMap(secret => {
            const title = secret.data.title || secret.recordUid;
            return secret.data.fields.map((field: any) => ({
                label: `${title} - ${field.label || field.type}`,
                description: field.type,
                detail: `Record: ${secret.recordUid}`,
                secret: secret,
                field: field
            }));
        });

        const selectedItem = await vscode.window.showQuickPick(items, {
            placeHolder: 'Search and select secret to copy',
            matchOnDescription: true,
            matchOnDetail: true
        });

        if (!selectedItem) return;

        await this.copySecretField(selectedItem.secret, selectedItem.field);
    }

    private async copyFromFavorites(): Promise<void> {
        const favorites = this.getFavorites();
        
        if (favorites.length === 0) {
            const action = await vscode.window.showInformationMessage(
                'No favorite secrets found',
                'Add Favorites'
            );
            if (action === 'Add Favorites') {
                await this.manageFavorites();
            }
            return;
        }

        const items = favorites.map(fav => {
            const secret = this.ksmService.getSecrets().find(s => s.recordUid === fav.recordUid);
            return {
                label: `$(star) ${fav.displayName}`,
                description: fav.fieldName,
                detail: `Last used: ${new Date(fav.lastUsed).toLocaleDateString()}`,
                favorite: fav,
                secret: secret
            };
        }).filter(item => item.secret); // Only show favorites that still exist

        const selectedItem = await vscode.window.showQuickPick(items, {
            placeHolder: 'Select favorite secret to copy'
        });

        if (!selectedItem) return;

        const field = selectedItem.secret!.data.fields.find((f: any) => 
            f.label === selectedItem.favorite.fieldName || f.type === selectedItem.favorite.fieldName
        );

        if (field) {
            await this.copySecretField(selectedItem.secret!, field);
            await this.updateFavoriteLastUsed(selectedItem.favorite.recordUid, selectedItem.favorite.fieldName);
        }
    }

    private async copyFromRecent(): Promise<void> {
        const recent = this.getRecent();
        
        if (recent.length === 0) {
            vscode.window.showInformationMessage('No recent secrets found');
            return;
        }

        const items = recent.map(rec => {
            const secret = this.ksmService.getSecrets().find(s => s.recordUid === rec.recordUid);
            return {
                label: `$(history) ${rec.displayName}`,
                description: rec.fieldName,
                detail: `Used: ${new Date(rec.lastUsed).toLocaleString()}`,
                recent: rec,
                secret: secret
            };
        }).filter(item => item.secret);

        const selectedItem = await vscode.window.showQuickPick(items, {
            placeHolder: 'Select recent secret to copy'
        });

        if (!selectedItem) return;

        const field = selectedItem.secret!.data.fields.find((f: any) => 
            f.label === selectedItem.recent.fieldName || f.type === selectedItem.recent.fieldName
        );

        if (field) {
            await this.copySecretField(selectedItem.secret!, field);
        }
    }

    private async manageFavorites(): Promise<void> {
        const action = await vscode.window.showQuickPick([
            { label: '$(add) Add Favorite', action: 'add' },
            { label: '$(remove) Remove Favorite', action: 'remove' }
        ], { placeHolder: 'Manage favorites' });

        if (!action) return;

        if (action.action === 'add') {
            await this.addFavorite();
        } else {
            await this.removeFavorite();
        }
    }

    private async addFavorite(): Promise<void> {
        const secrets = this.ksmService.getSecrets();
        const favorites = this.getFavorites();
        
        const items = secrets.flatMap(secret => {
            const title = secret.data.title || secret.recordUid;
            return secret.data.fields.map((field: any) => {
                const fieldName = field.label || field.type;
                const isAlreadyFavorite = favorites.some(fav => 
                    fav.recordUid === secret.recordUid && fav.fieldName === fieldName
                );
                
                return {
                    label: isAlreadyFavorite ? 
                        `$(star-full) ${title} - ${fieldName}` : 
                        `$(star-empty) ${title} - ${fieldName}`,
                    description: field.type,
                    detail: isAlreadyFavorite ? 'Already in favorites' : 'Click to add to favorites',
                    secret: secret,
                    field: field,
                    isAlreadyFavorite
                };
            });
        });

        const selectedItem = await vscode.window.showQuickPick(items, {
            placeHolder: 'Select secret to add to favorites'
        });

        if (!selectedItem || selectedItem.isAlreadyFavorite) return;

        const displayName = await vscode.window.showInputBox({
            prompt: 'Enter display name for this favorite',
            value: `${selectedItem.secret.data.title || selectedItem.secret.recordUid} - ${selectedItem.field.label || selectedItem.field.type}`,
            validateInput: (value) => {
                if (!value || value.trim().length < 2) {
                    return 'Display name must be at least 2 characters';
                }
                return null;
            }
        });

        if (!displayName) return;

        await this.addToFavorites(selectedItem.secret.recordUid, selectedItem.field.label || selectedItem.field.type, displayName);
        vscode.window.showInformationMessage(`Added "${displayName}" to favorites`);
    }

    private async removeFavorite(): Promise<void> {
        const favorites = this.getFavorites();
        
        if (favorites.length === 0) {
            vscode.window.showInformationMessage('No favorites to remove');
            return;
        }

        const items = favorites.map(fav => ({
            label: `$(star-full) ${fav.displayName}`,
            description: fav.fieldName,
            detail: `Record: ${fav.recordUid}`,
            favorite: fav
        }));

        const selectedItem = await vscode.window.showQuickPick(items, {
            placeHolder: 'Select favorite to remove'
        });

        if (!selectedItem) return;

        await this.removeFromFavorites(selectedItem.favorite.recordUid, selectedItem.favorite.fieldName);
        vscode.window.showInformationMessage(`Removed "${selectedItem.favorite.displayName}" from favorites`);
    }

    private async copySecretField(secret: any, field: any): Promise<void> {
        try {
            const value = field.value && field.value.length > 0 ? field.value[0] : '';
            
            if (!value) {
                vscode.window.showWarningMessage('Secret field is empty');
                return;
            }

            await this.clipboard.writeText(value);
            
            // Add to recent
            await this.addToRecent(secret.recordUid, field.label || field.type, 
                secret.data.title || secret.recordUid);

            // Show success message with auto-clear info
            const message = `Copied ${field.label || field.type} (will auto-clear in 30s)`;
            vscode.window.showInformationMessage(message);

            // Setup auto-clear
            this.setupAutoClearing(value);

        } catch (error) {
            vscode.window.showErrorMessage(`Failed to copy secret: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    private setupAutoClearing(copiedValue: string): void {
        // Check if auto-clear is enabled in settings
        const autoCleanEnabled = this.settingsService?.getClipboardAutoClear() ?? true;
        if (!autoCleanEnabled) {
            return;
        }

        // Clear any existing timeout
        if (this.clipboardTimeout) {
            clearTimeout(this.clipboardTimeout);
        }

        // Set new timeout to clear clipboard after 30 seconds
        this.clipboardTimeout = setTimeout(async () => {
            try {
                const currentClipboard = await this.clipboard.readText();
                if (currentClipboard === copiedValue) {
                    await this.clipboard.writeText('');
                    vscode.window.showInformationMessage('Clipboard cleared for security');
                }
            } catch (error) {
                // Ignore clipboard access errors
            }
        }, 30000);
    }

    // Favorites management
    private getFavorites(): FavoriteSecret[] {
        return this.context.globalState.get<FavoriteSecret[]>(QuickAccessService.FAVORITES_KEY, []);
    }

    public async addToFavorites(recordUid: string, fieldName: string, displayName: string): Promise<void> {
        const favorites = this.getFavorites();
        const newFavorite: FavoriteSecret = {
            recordUid,
            fieldName,
            displayName,
            lastUsed: Date.now()
        };
        
        favorites.push(newFavorite);
        await this.context.globalState.update(QuickAccessService.FAVORITES_KEY, favorites);
    }

    private async removeFromFavorites(recordUid: string, fieldName: string): Promise<void> {
        const favorites = this.getFavorites();
        const filtered = favorites.filter(fav => 
            !(fav.recordUid === recordUid && fav.fieldName === fieldName)
        );
        await this.context.globalState.update(QuickAccessService.FAVORITES_KEY, filtered);
    }

    private async updateFavoriteLastUsed(recordUid: string, fieldName: string): Promise<void> {
        const favorites = this.getFavorites();
        const favorite = favorites.find(fav => 
            fav.recordUid === recordUid && fav.fieldName === fieldName
        );
        
        if (favorite) {
            favorite.lastUsed = Date.now();
            await this.context.globalState.update(QuickAccessService.FAVORITES_KEY, favorites);
        }
    }

    // Recent secrets management
    private getRecent(): FavoriteSecret[] {
        const recent = this.context.globalState.get<FavoriteSecret[]>(QuickAccessService.RECENT_KEY, []);
        return recent.sort((a, b) => b.lastUsed - a.lastUsed).slice(0, 10); // Keep last 10
    }

    private async addToRecent(recordUid: string, fieldName: string, displayName: string): Promise<void> {
        const recent = this.context.globalState.get<FavoriteSecret[]>(QuickAccessService.RECENT_KEY, []);
        
        // Remove existing entry if it exists
        const filtered = recent.filter(r => 
            !(r.recordUid === recordUid && r.fieldName === fieldName)
        );
        
        // Add new entry at the beginning
        filtered.unshift({
            recordUid,
            fieldName,
            displayName,
            lastUsed: Date.now()
        });
        
        // Keep only last 10
        const trimmed = filtered.slice(0, 10);
        
        await this.context.globalState.update(QuickAccessService.RECENT_KEY, trimmed);
    }

    public dispose(): void {
        if (this.clipboardTimeout) {
            clearTimeout(this.clipboardTimeout);
        }
    }
}