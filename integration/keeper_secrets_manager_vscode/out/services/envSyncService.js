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
exports.EnvSyncService = void 0;
const vscode = __importStar(require("vscode"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
class EnvSyncService {
    constructor(ksmService) {
        this.ksmService = ksmService;
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            throw new Error('No workspace folder found');
        }
        this.workspaceRoot = workspaceFolder.uri.fsPath;
    }
    async findEnvFiles() {
        const envFileNames = ['.env', '.env.local', '.env.development', '.env.production', '.env.test'];
        const envFiles = [];
        for (const fileName of envFileNames) {
            const filePath = path.join(this.workspaceRoot, fileName);
            envFiles.push({
                path: filePath,
                name: fileName,
                exists: fs.existsSync(filePath)
            });
        }
        return envFiles;
    }
    parseEnvFile(filePath) {
        if (!fs.existsSync(filePath)) {
            return [];
        }
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        const variables = [];
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            // Look for commented keeper references
            // Format: # VAR_NAME=postgresql://keeper://UID/field/username:keeper://UID/field/password@keeper://UID/field/host:keeper://UID/field/port/db
            const commentMatch = line.match(/^#\s*(\w+)=(.+)$/);
            if (commentMatch) {
                const [, varName, value] = commentMatch;
                const references = this.parseKeeperReferences(value);
                if (references.length > 0) {
                    // Look for the actual env var line
                    const actualVarLine = lines.findIndex(l => l.trim().startsWith(`${varName}=`));
                    variables.push({
                        name: varName,
                        commentLine: line,
                        valueLine: actualVarLine !== -1 ? lines[actualVarLine] : `${varName}=`,
                        lineNumber: i,
                        references
                    });
                }
            }
        }
        return variables;
    }
    parseKeeperReferences(value) {
        const references = [];
        const regex = /keeper:\/\/([^\/]+)\/field\/([^\/\s:@]+)/g;
        let match;
        while ((match = regex.exec(value)) !== null) {
            references.push({
                uid: match[1],
                field: match[2]
            });
        }
        return references;
    }
    async resolveReferences(value) {
        const regex = /keeper:\/\/([^\/]+)\/field\/([^\/\s:@]+)/g;
        let resolvedValue = value;
        const matches = Array.from(value.matchAll(regex));
        for (const match of matches) {
            const [fullMatch, uid, field] = match;
            try {
                const secretValue = await this.ksmService.resolveNotation(`\${${fullMatch}}`);
                resolvedValue = resolvedValue.replace(fullMatch, secretValue);
            }
            catch (error) {
                vscode.window.showWarningMessage(`Failed to resolve ${fullMatch}: ${error instanceof Error ? error.message : 'Unknown error'}`);
                // Keep the original reference if resolution fails
            }
        }
        return resolvedValue;
    }
    async syncEnvFile(filePath, dryRun = false, backup = false) {
        if (!fs.existsSync(filePath)) {
            throw new Error(`File not found: ${filePath}`);
        }
        // Create backup if requested
        if (backup && !dryRun) {
            const backupPath = `${filePath}.backup.${Date.now()}`;
            fs.copyFileSync(filePath, backupPath);
            vscode.window.showInformationMessage(`Backup created: ${path.basename(backupPath)}`);
        }
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        const variables = this.parseEnvFile(filePath);
        const updated = [];
        const errors = [];
        for (const variable of variables) {
            try {
                // Extract the value part after the equals sign from the comment
                const valueMatch = variable.commentLine.match(/^#\s*\w+=(.+)$/);
                if (valueMatch) {
                    const templateValue = valueMatch[1];
                    const resolvedValue = await this.resolveReferences(templateValue);
                    // Find the actual env var line and update it
                    const envVarIndex = lines.findIndex(l => l.trim().startsWith(`${variable.name}=`));
                    if (envVarIndex !== -1) {
                        if (!dryRun) {
                            lines[envVarIndex] = `${variable.name}=${resolvedValue}`;
                        }
                        updated.push(`${variable.name}=${resolvedValue}`);
                    }
                    else {
                        // Add new env var if it doesn't exist
                        if (!dryRun) {
                            lines.push(`${variable.name}=${resolvedValue}`);
                        }
                        updated.push(`${variable.name}=${resolvedValue} (new)`);
                    }
                }
            }
            catch (error) {
                const errorMsg = `${variable.name}: ${error instanceof Error ? error.message : 'Unknown error'}`;
                errors.push(errorMsg);
            }
        }
        if (!dryRun) {
            fs.writeFileSync(filePath, lines.join('\n'));
        }
        return { updated, errors };
    }
    async addSecretToEnvFile(filePath, varName, uid, field, templateValue) {
        let content = '';
        if (fs.existsSync(filePath)) {
            content = fs.readFileSync(filePath, 'utf8');
        }
        const lines = content.split('\n');
        // Create the template value
        const template = templateValue || `keeper://${uid}/field/${field}`;
        // Add comment line
        const commentLine = `# ${varName}=${template}`;
        // Add actual env var line with placeholder
        const envLine = `${varName}=placeholder`;
        // Check if variable already exists
        const existingCommentIndex = lines.findIndex(l => l.trim().startsWith(`# ${varName}=`));
        const existingVarIndex = lines.findIndex(l => l.trim().startsWith(`${varName}=`));
        if (existingCommentIndex !== -1) {
            // Update existing comment
            lines[existingCommentIndex] = commentLine;
        }
        else {
            // Add new comment
            lines.push(commentLine);
        }
        if (existingVarIndex !== -1) {
            // Update existing var
            lines[existingVarIndex] = envLine;
        }
        else {
            // Add new var
            lines.push(envLine);
        }
        fs.writeFileSync(filePath, lines.join('\n'));
        vscode.window.showInformationMessage(`Added ${varName} to ${path.basename(filePath)}`);
    }
    async generateEnvTemplate(filePath, selectedSecrets) {
        const lines = [];
        // Add header comment
        lines.push('# Environment variables with Keeper secret references');
        lines.push('# Run "Keeper: Sync Environment Secrets" to populate with actual values');
        lines.push('');
        for (const secret of selectedSecrets) {
            lines.push(`# ${secret.varName}=keeper://${secret.uid}/field/${secret.field}`);
            lines.push(`${secret.varName}=placeholder`);
            lines.push('');
        }
        fs.writeFileSync(filePath, lines.join('\n'));
        vscode.window.showInformationMessage(`Generated template: ${path.basename(filePath)}`);
    }
}
exports.EnvSyncService = EnvSyncService;
//# sourceMappingURL=envSyncService.js.map