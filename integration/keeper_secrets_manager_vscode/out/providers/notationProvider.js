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
exports.NotationProvider = void 0;
const vscode = __importStar(require("vscode"));
class NotationProvider {
    constructor(ksmService) {
        this.ksmService = ksmService;
    }
    async provideCompletionItems(document, position, token, context) {
        if (!this.ksmService.isAuthenticated()) {
            return null;
        }
        const lineText = document.lineAt(position).text;
        const textBeforeCursor = lineText.substring(0, position.character);
        // Check if we're in a keeper notation context
        const keeperMatch = textBeforeCursor.match(/\$\{keeper:\/\/([^\/]*)$/);
        if (keeperMatch) {
            // Provide UID completions
            return this.provideUidCompletions();
        }
        const fieldMatch = textBeforeCursor.match(/\$\{keeper:\/\/([^\/]+)\/field\/([^}]*)$/);
        if (fieldMatch) {
            // Provide field completions for the specific record
            const uid = fieldMatch[1];
            return this.provideFieldCompletions(uid);
        }
        const startMatch = textBeforeCursor.match(/\$\{keeper$/);
        if (startMatch) {
            // Provide the basic notation start
            const item = new vscode.CompletionItem('keeper://', vscode.CompletionItemKind.Snippet);
            item.insertText = 'keeper://';
            item.documentation = 'Keeper Secrets Manager notation';
            return [item];
        }
        return null;
    }
    provideUidCompletions() {
        const secrets = this.ksmService.getSecrets();
        return secrets.map(secret => {
            const item = new vscode.CompletionItem(secret.recordUid, vscode.CompletionItemKind.Value);
            item.detail = secret.data.title || 'No title';
            item.documentation = `Record: ${secret.data.title || secret.recordUid}`;
            item.insertText = `${secret.recordUid}/field/`;
            return item;
        });
    }
    provideFieldCompletions(uid) {
        const record = this.ksmService.getRecordByUid(uid);
        if (!record) {
            return [];
        }
        return record.data.fields.map((field) => {
            const fieldName = field.label || field.type;
            const item = new vscode.CompletionItem(fieldName, vscode.CompletionItemKind.Field);
            item.detail = field.type;
            item.documentation = `Field: ${fieldName} (${field.type})`;
            item.insertText = `${fieldName}}`;
            return item;
        });
    }
    async provideHover(document, position, token) {
        if (!this.ksmService.isAuthenticated()) {
            return null;
        }
        // First check for existing keeper notation
        const keeperRange = document.getWordRangeAtPosition(position, /\$\{keeper:\/\/[^}]+\}/);
        if (keeperRange) {
            const notation = document.getText(keeperRange);
            try {
                const value = await this.ksmService.resolveNotation(notation);
                const markdown = new vscode.MarkdownString();
                markdown.appendCodeblock(notation, 'text');
                markdown.appendText('Resolves to: ');
                markdown.appendCodeblock('***', 'text'); // Hide actual value for security
                return new vscode.Hover(markdown, keeperRange);
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                const cleanError = errorMessage
                    .replace(/Record with UID .* not found/, 'Record not found')
                    .replace(/Field .* not found in record .*/, 'Field not found');
                const markdown = new vscode.MarkdownString();
                markdown.appendCodeblock(notation, 'text');
                markdown.appendText(`❌ ${cleanError}`);
                return new vscode.Hover(markdown, keeperRange);
            }
        }
        // Check for potential hardcoded secrets
        const secretInfo = this.detectPotentialSecret(document, position);
        if (secretInfo) {
            const markdown = new vscode.MarkdownString();
            markdown.isTrusted = true;
            markdown.supportHtml = true;
            markdown.appendMarkdown(`**🔐 Potential Secret Detected**\n\n`);
            markdown.appendMarkdown(`Type: ${secretInfo.type}\n\n`);
            markdown.appendMarkdown(`Value: \`${secretInfo.maskedValue}\`\n\n`);
            // Add action button
            const saveCommand = vscode.Uri.parse(`command:keeper.saveSecret?${encodeURIComponent(JSON.stringify({
                value: secretInfo.value,
                type: secretInfo.type,
                range: {
                    start: { line: secretInfo.range.start.line, character: secretInfo.range.start.character },
                    end: { line: secretInfo.range.end.line, character: secretInfo.range.end.character }
                },
                document: document.uri.toString()
            }))}`);
            markdown.appendMarkdown(`[💾 Save to Keeper](${saveCommand})`);
            return new vscode.Hover(markdown, secretInfo.range);
        }
        return null;
    }
    detectPotentialSecret(document, position) {
        const line = document.lineAt(position);
        const text = line.text;
        const char = position.character;
        // Common secret patterns
        const patterns = [
            // API Keys
            { regex: /(['"])(sk-[a-zA-Z0-9]{32,})\1/g, type: 'API Key' },
            { regex: /(['"])(pk_[a-zA-Z0-9]{32,})\1/g, type: 'Public Key' },
            { regex: /(['"])(rk_[a-zA-Z0-9]{32,})\1/g, type: 'Restricted Key' },
            { regex: /(['"])(AKIA[A-Z0-9]{16})\1/g, type: 'AWS Access Key' },
            { regex: /(['"])(ASIA[A-Z0-9]{16})\1/g, type: 'AWS Session Token' },
            // Database Connection Strings
            { regex: /(['"])(postgresql:\/\/[^'"]+)\1/g, type: 'Database Connection' },
            { regex: /(['"])(mysql:\/\/[^'"]+)\1/g, type: 'Database Connection' },
            { regex: /(['"])(mongodb:\/\/[^'"]+)\1/g, type: 'Database Connection' },
            { regex: /(['"])(redis:\/\/[^'"]+)\1/g, type: 'Database Connection' },
            // JWT Tokens
            { regex: /(['"])(eyJ[a-zA-Z0-9+/=]+\.eyJ[a-zA-Z0-9+/=]+\.[a-zA-Z0-9+/=_-]+)\1/g, type: 'JWT Token' },
            // Generic long strings that might be secrets
            { regex: /(['"])([a-zA-Z0-9+/=]{32,})\1/g, type: 'Potential Secret' },
            // URLs with credentials
            { regex: /(['"])(https?:\/\/[^:]+:[^@]+@[^'"]+)\1/g, type: 'URL with Credentials' },
            // SSH private keys
            { regex: /(-----BEGIN [A-Z ]+PRIVATE KEY-----[^-]+-----END [A-Z ]+PRIVATE KEY-----)/g, type: 'SSH Private Key' },
            // Common password patterns
            { regex: /(['"])(password|pwd|pass|secret|token|key|auth)['"]\s*[:=]\s*['"]([^'"]{8,})\1/gi, type: 'Password' }
        ];
        for (const pattern of patterns) {
            pattern.regex.lastIndex = 0; // Reset regex state
            let match;
            while ((match = pattern.regex.exec(text)) !== null) {
                const matchStart = match.index;
                const matchEnd = matchStart + match[0].length;
                // Check if cursor is within the match
                if (char >= matchStart && char <= matchEnd) {
                    // Extract the actual secret value (without quotes)
                    const secretValue = match[2] || match[1];
                    // Skip if it's too short or looks like a placeholder
                    if (secretValue.length < 8 ||
                        secretValue.includes('${') ||
                        secretValue.includes('{{') ||
                        secretValue.toLowerCase().includes('placeholder') ||
                        secretValue.toLowerCase().includes('example') ||
                        secretValue.toLowerCase().includes('your_') ||
                        secretValue.toLowerCase().includes('replace') ||
                        secretValue === 'password' ||
                        secretValue === 'secret' ||
                        secretValue === 'token') {
                        continue;
                    }
                    const range = new vscode.Range(new vscode.Position(line.lineNumber, matchStart), new vscode.Position(line.lineNumber, matchEnd));
                    return {
                        type: pattern.type,
                        value: secretValue,
                        maskedValue: secretValue.length > 8 ?
                            secretValue.substring(0, 4) + '***' + secretValue.substring(secretValue.length - 4) :
                            '***',
                        range
                    };
                }
            }
        }
        return null;
    }
}
exports.NotationProvider = NotationProvider;
//# sourceMappingURL=notationProvider.js.map