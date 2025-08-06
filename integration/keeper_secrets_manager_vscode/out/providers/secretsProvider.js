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
exports.SecretsProvider = void 0;
const vscode = __importStar(require("vscode"));
class SecretsProvider {
    constructor(ksmService) {
        this.ksmService = ksmService;
    }
    async showSecretsList() {
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
    async showSecretDetails(secret) {
        const fields = secret.data.fields.map((field) => ({
            label: field.label || field.type,
            description: field.type,
            detail: field.value[0] ? '***' : 'Empty',
            field
        }));
        const selectedField = await vscode.window.showQuickPick(fields, {
            placeHolder: 'Select a field to copy or insert'
        });
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
    async insertFieldReference(secret, field) {
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
    async insertSecretReference() {
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
            const fieldItems = selectedSecret.secret.data.fields.map((field) => ({
                label: field.label || field.type,
                description: field.type,
                field
            }));
            const selectedField = await vscode.window.showQuickPick(fieldItems, {
                placeHolder: 'Select a field'
            });
            if (selectedField) {
                await this.insertFieldReference(selectedSecret.secret, selectedField.field);
            }
        }
    }
}
exports.SecretsProvider = SecretsProvider;
//# sourceMappingURL=secretsProvider.js.map