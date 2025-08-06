import * as vscode from 'vscode';
import { KSMService } from '../services/ksmService';
import { KeeperRecord } from '@keeper-security/secrets-manager-core';

export class SecretsProvider {
    private ksmService: KSMService;

    constructor(ksmService: KSMService) {
        this.ksmService = ksmService;
    }

    async showSecretsList(): Promise<void> {
        if (!this.ksmService.isAuthenticated()) {
            vscode.window.showWarningMessage('Please authenticate first');
            return;
        }

        const secrets = this.ksmService.getSecrets();
        
        if (secrets.length === 0) {
            vscode.window.showInformationMessage('No secrets found');
            return;
        }

        const items = secrets.map(secret => ({
            label: secret.data.title || secret.recordUid,
            description: secret.recordUid,
            detail: `${secret.data.fields.length} fields`,
            secret
        }));

        const selected = await vscode.window.showQuickPick(items, {
            placeHolder: 'Select a secret to view details'
        });

        if (selected) {
            await this.showSecretDetails(selected.secret);
        }
    }

    private async showSecretDetails(secret: KeeperRecord): Promise<void> {
        const fields = secret.data.fields.map((field: any) => ({
            label: field.label || field.type,
            description: field.type,
            detail: field.value[0] ? '***' : 'Empty',
            field
        }));

        const selectedField = await vscode.window.showQuickPick(fields, {
            placeHolder: 'Select a field to copy or insert'
        }) as any;

        if (selectedField) {
            const actions = ['Copy Value', 'Insert Reference', 'Copy Record UID', 'Cancel'];
            const action = await vscode.window.showQuickPick(actions, {
                placeHolder: 'What would you like to do with this field?'
            });

            switch (action) {
                case 'Copy Value':
                    await vscode.env.clipboard.writeText(selectedField.field.value[0] || '');
                    vscode.window.showInformationMessage('Field value copied to clipboard');
                    break;
                case 'Insert Reference':
                    await this.insertFieldReference(secret, selectedField.field);
                    break;
                case 'Copy Record UID':
                    await vscode.env.clipboard.writeText(secret.recordUid);
                    vscode.window.showInformationMessage('Record UID copied to clipboard');
                    break;
            }
        }
    }

    private async insertFieldReference(secret: KeeperRecord, field: any): Promise<void> {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor');
            return;
        }

        const fieldName = field.label || field.type;
        const notation = `\${keeper://${secret.recordUid}/field/${fieldName}}`;
        
        const position = editor.selection.active;
        await editor.edit(editBuilder => {
            editBuilder.insert(position, notation);
        });

        vscode.window.showInformationMessage('Secret reference inserted');
    }

    async insertSecretReference(): Promise<void> {
        if (!this.ksmService.isAuthenticated()) {
            vscode.window.showWarningMessage('Please authenticate first');
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor');
            return;
        }

        const secrets = this.ksmService.getSecrets();
        
        if (secrets.length === 0) {
            vscode.window.showInformationMessage('No secrets found');
            return;
        }

        const secretItems = secrets.map(secret => ({
            label: secret.data.title || secret.recordUid,
            description: secret.recordUid,
            secret
        }));

        const selectedSecret = await vscode.window.showQuickPick(secretItems, {
            placeHolder: 'Select a secret'
        });

        if (selectedSecret) {
            const fieldItems = selectedSecret.secret.data.fields.map((field: any) => ({
                label: field.label || field.type,
                description: field.type,
                field
            }));

            const selectedField = await vscode.window.showQuickPick(fieldItems, {
                placeHolder: 'Select a field'
            }) as any;

            if (selectedField) {
                await this.insertFieldReference(selectedSecret.secret, selectedField.field);
            }
        }
    }
}