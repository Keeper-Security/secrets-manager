import * as vscode from 'vscode';
import { KSMService } from './ksmService';

export interface CodeTemplate {
    name: string;
    description: string;
    language: string;
    category: string;
    code: string;
    placeholders: string[];
}

export class CodeGenerationService {
    private templates: CodeTemplate[] = [];

    constructor(private ksmService: KSMService) {
        this.initializeTemplates();
    }

    private initializeTemplates() {
        this.templates = [
            // Python Templates
            {
                name: "Basic Connection (File-based)",
                description: "Initialize KSM with file-based configuration",
                language: "python",
                category: "connection",
                code: `from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage

# Initialize file-based storage
storage = FileKeyValueStorage('{{CONFIG_FILE}}')
secrets_manager = SecretsManager(token='{{ONE_TIME_TOKEN}}', config=storage)

# Verify connection
try:
    secrets = secrets_manager.get_secrets()
    print(f"Connected successfully! Found {len(secrets)} secrets.")
except Exception as e:
    print(f"Connection failed: {e}")`,
                placeholders: ['CONFIG_FILE', 'ONE_TIME_TOKEN']
            },
            {
                name: "Basic Connection (In-memory)",
                description: "Initialize KSM with in-memory configuration",
                language: "python",
                category: "connection",
                code: `from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

# Initialize in-memory storage with base64 config
storage = InMemoryKeyValueStorage('{{BASE64_CONFIG}}')
secrets_manager = SecretsManager(config=storage)

# Verify connection
try:
    secrets = secrets_manager.get_secrets()
    print(f"Connected successfully! Found {len(secrets)} secrets.")
except Exception as e:
    print(f"Connection failed: {e}")`,
                placeholders: ['BASE64_CONFIG']
            },
            {
                name: "Get All Secrets",
                description: "Retrieve all secrets from the vault",
                language: "python",
                category: "retrieval",
                code: `# Get all secrets
secrets = secrets_manager.get_secrets()

# Process each secret
for secret in secrets:
    print(f"Record: {secret.title}")
    print(f"UID: {secret.uid}")
    
    # Access specific fields
    login_field = secret.field('login')
    password_field = secret.field('password')
    
    if login_field:
        print(f"Login: {login_field[0].value}")
    if password_field:
        print(f"Password: {'*' * len(password_field[0].value)}")
    
    print("---")`,
                placeholders: []
            },
            {
                name: "Get Specific Secrets",
                description: "Retrieve specific secrets by UID",
                language: "python",
                category: "retrieval",
                code: `# Get specific secrets by UID
secret_uids = ['{{SECRET_UID_1}}', '{{SECRET_UID_2}}']
secrets = secrets_manager.get_secrets(uids=secret_uids)

# Process retrieved secrets
for secret in secrets:
    print(f"Retrieved secret: {secret.title}")
    
    # Access fields safely
    fields = secret.dict.get('fields', [])
    for field in fields:
        field_type = field.get('type', 'unknown')
        field_value = field.get('value', [''])[0]
        
        if field_type == 'password':
            print(f"{field_type}: {'*' * len(field_value)}")
        else:
            print(f"{field_type}: {field_value}")`,
                placeholders: ['SECRET_UID_1', 'SECRET_UID_2']
            },
            {
                name: "Create New Record",
                description: "Create a new login record",
                language: "python",
                category: "record",
                code: `from keeper_secrets_manager_core.dto.dtos import RecordCreate, RecordField
from keeper_secrets_manager_core.utils import generate_password

# Create new login record
new_record = RecordCreate(
    record_type='login',
    title='{{RECORD_TITLE}}'
)

# Add fields
new_record.fields = [
    RecordField(field_type='login', value=['{{USERNAME}}']),
    RecordField(field_type='password', value=[generate_password(length=16)]),
    RecordField(field_type='url', value=['{{URL}}']),
    RecordField(field_type='notes', value=['{{NOTES}}'])
]

# Create the record
try:
    record_uid = secrets_manager.create_secret('{{FOLDER_UID}}', new_record)
    print(f"Record created successfully! UID: {record_uid}")
except Exception as e:
    print(f"Failed to create record: {e}")`,
                placeholders: ['RECORD_TITLE', 'USERNAME', 'URL', 'NOTES', 'FOLDER_UID']
            },
            {
                name: "Upload File to Record",
                description: "Upload a file to an existing record",
                language: "python",
                category: "file",
                code: `import os

# Upload file to record
file_path = '{{FILE_PATH}}'
record_uid = '{{RECORD_UID}}'

if os.path.exists(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
            
        # Upload file
        file_uid = secrets_manager.upload_file(
            record_uid=record_uid,
            file_data=file_data,
            file_name=os.path.basename(file_path)
        )
        
        print(f"File uploaded successfully! File UID: {file_uid}")
        
    except Exception as e:
        print(f"Failed to upload file: {e}")
else:
    print(f"File not found: {file_path}")`,
                placeholders: ['FILE_PATH', 'RECORD_UID']
            },

            // JavaScript Templates
            {
                name: "Basic Connection (File-based)",
                description: "Initialize KSM with file-based configuration",
                language: "javascript",
                category: "connection",
                code: `const { getSecrets, initializeStorage, localConfigStorage } = require("@keeper-security/secrets-manager-core");

async function initializeKSM() {
    try {
        // Initialize file-based storage
        const storage = localConfigStorage('{{CONFIG_FILE}}');
        await initializeStorage(storage, '{{ONE_TIME_TOKEN}}');
        
        // Verify connection
        const options = { storage: storage };
        const { records } = await getSecrets(options);
        
        console.log(\`Connected successfully! Found \${records.length} secrets.\`);
        return options;
        
    } catch (error) {
        console.error('Connection failed:', error);
        throw error;
    }
}

// Initialize and use
initializeKSM().then(options => {
    console.log('KSM initialized successfully');
}).catch(error => {
    console.error('Initialization failed:', error);
});`,
                placeholders: ['CONFIG_FILE', 'ONE_TIME_TOKEN']
            },
            {
                name: "Basic Connection (In-memory)",
                description: "Initialize KSM with in-memory configuration",
                language: "javascript",
                category: "connection",
                code: `const { getSecrets, memoryStorage } = require("@keeper-security/secrets-manager-core");

async function initializeKSM() {
    try {
        // Initialize in-memory storage with base64 config
        const storage = memoryStorage('{{BASE64_CONFIG}}');
        const options = { storage: storage };
        
        // Verify connection
        const { records } = await getSecrets(options);
        
        console.log(\`Connected successfully! Found \${records.length} secrets.\`);
        return options;
        
    } catch (error) {
        console.error('Connection failed:', error);
        throw error;
    }
}

// Initialize and use
initializeKSM().then(options => {
    console.log('KSM initialized successfully');
}).catch(error => {
    console.error('Initialization failed:', error);
});`,
                placeholders: ['BASE64_CONFIG']
            },
            {
                name: "Get All Secrets",
                description: "Retrieve all secrets from the vault",
                language: "javascript",
                category: "retrieval",
                code: `const { getSecrets } = require("@keeper-security/secrets-manager-core");

async function getAllSecrets(options) {
    try {
        const { records } = await getSecrets(options);
        
        console.log(\`Found \${records.length} secrets\`);
        
        // Process each secret
        records.forEach(record => {
            console.log(\`Record: \${record.data.title}\`);
            console.log(\`UID: \${record.recordUid}\`);
            
            // Access specific fields
            const loginField = record.data.fields.find(f => f.type === 'login');
            const passwordField = record.data.fields.find(f => f.type === 'password');
            
            if (loginField && loginField.value) {
                console.log(\`Login: \${loginField.value[0]}\`);
            }
            if (passwordField && passwordField.value) {
                console.log(\`Password: \${'*'.repeat(passwordField.value[0].length)}\`);
            }
            
            console.log('---');
        });
        
        return records;
        
    } catch (error) {
        console.error('Failed to retrieve secrets:', error);
        throw error;
    }
}

// Usage (assuming options is already configured)
getAllSecrets(options);`,
                placeholders: []
            },
            {
                name: "Create New Record",
                description: "Create a new login record",
                language: "javascript",
                category: "record",
                code: `const { createSecret, generatePassword } = require("@keeper-security/secrets-manager-core");

async function createLoginRecord(options) {
    try {
        // Generate a secure password
        const password = await generatePassword({
            length: 16,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true
        });
        
        // Create record data
        const recordData = {
            title: '{{RECORD_TITLE}}',
            type: 'login',
            fields: [
                {
                    type: 'login',
                    value: ['{{USERNAME}}']
                },
                {
                    type: 'password',
                    value: [password]
                },
                {
                    type: 'url',
                    value: ['{{URL}}']
                },
                {
                    type: 'notes',
                    value: ['{{NOTES}}']
                }
            ]
        };
        
        // Create the record
        const recordUid = await createSecret(options, '{{FOLDER_UID}}', recordData);
        
        console.log(\`Record created successfully! UID: \${recordUid}\`);
        return recordUid;
        
    } catch (error) {
        console.error('Failed to create record:', error);
        throw error;
    }
}

// Usage (assuming options is already configured)
createLoginRecord(options);`,
                placeholders: ['RECORD_TITLE', 'USERNAME', 'URL', 'NOTES', 'FOLDER_UID']
            },

            // Java Templates
            {
                name: "Basic Connection (File-based)",
                description: "Initialize KSM with file-based configuration",
                language: "java",
                category: "connection",
                code: `import com.keepersecurity.secretsManager.core.*;
import static com.keepersecurity.secretsManager.core.SecretsManager.initializeStorage;

public class KSMConnection {
    public static void main(String[] args) {
        try {
            // Initialize file-based storage
            LocalConfigStorage storage = new LocalConfigStorage("{{CONFIG_FILE}}");
            initializeStorage(storage, "{{ONE_TIME_TOKEN}}");
            
            // Create SecretsManager options
            SecretsManagerOptions options = new SecretsManagerOptions(storage);
            
            // Verify connection
            KeeperSecrets secrets = SecretsManager.getSecrets(options);
            System.out.println("Connected successfully! Found " + secrets.getRecords().size() + " secrets.");
            
        } catch (Exception e) {
            System.err.println("Connection failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}`,
                placeholders: ['CONFIG_FILE', 'ONE_TIME_TOKEN']
            },
            {
                name: "Get All Secrets",
                description: "Retrieve all secrets from the vault",
                language: "java",
                category: "retrieval",
                code: `import com.keepersecurity.secretsManager.core.*;
import java.util.List;

public void getAllSecrets(SecretsManagerOptions options) {
    try {
        KeeperSecrets secrets = SecretsManager.getSecrets(options);
        List<KeeperRecord> records = secrets.getRecords();
        
        System.out.println("Found " + records.size() + " secrets");
        
        // Process each secret
        for (KeeperRecord record : records) {
            System.out.println("Record: " + record.getData().getTitle());
            System.out.println("UID: " + record.getRecordUid());
            
            // Access specific fields
            List<KeeperRecordField> fields = record.getData().getFields();
            for (KeeperRecordField field : fields) {
                String fieldType = field.getType();
                List<String> values = field.getValue();
                
                if (fieldType.equals("password") && !values.isEmpty()) {
                    System.out.println("Password: " + "*".repeat(values.get(0).length()));
                } else if (!values.isEmpty()) {
                    System.out.println(fieldType + ": " + values.get(0));
                }
            }
            
            System.out.println("---");
        }
        
    } catch (Exception e) {
        System.err.println("Failed to retrieve secrets: " + e.getMessage());
        e.printStackTrace();
    }
}`,
                placeholders: []
            },

            // Go Templates
            {
                name: "Basic Connection (File-based)",
                description: "Initialize KSM with file-based configuration",
                language: "go",
                category: "connection",
                code: `package main

import (
    "fmt"
    "log"
    
    ksm "github.com/keeper-security/secrets-manager-go/core"
)

func main() {
    // Initialize file-based storage
    fileStorage := ksm.NewFileKeyValueStorage("{{CONFIG_FILE}}")
    
    // Create SecretsManager
    sm := ksm.NewSecretsManager(&ksm.ClientOptions{
        Config: fileStorage,
        Token:  "{{ONE_TIME_TOKEN}}",
    })
    
    // Verify connection
    secrets, err := sm.GetSecrets(nil)
    if err != nil {
        log.Fatalf("Connection failed: %v", err)
    }
    
    fmt.Printf("Connected successfully! Found %d secrets.\\n", len(secrets.Records))
}`,
                placeholders: ['CONFIG_FILE', 'ONE_TIME_TOKEN']
            },
            {
                name: "Get All Secrets",
                description: "Retrieve all secrets from the vault",
                language: "go",
                category: "retrieval",
                code: `package main

import (
    "fmt"
    "log"
    "strings"
    
    ksm "github.com/keeper-security/secrets-manager-go/core"
)

func getAllSecrets(sm *ksm.SecretsManager) {
    secrets, err := sm.GetSecrets(nil)
    if err != nil {
        log.Fatalf("Failed to retrieve secrets: %v", err)
    }
    
    fmt.Printf("Found %d secrets\\n", len(secrets.Records))
    
    // Process each secret
    for _, record := range secrets.Records {
        fmt.Printf("Record: %s\\n", record.Data.Title)
        fmt.Printf("UID: %s\\n", record.RecordUid)
        
        // Access specific fields
        for _, field := range record.Data.Fields {
            fieldType := field.Type
            if len(field.Value) > 0 {
                value := field.Value[0]
                
                if fieldType == "password" {
                    fmt.Printf("Password: %s\\n", strings.Repeat("*", len(value)))
                } else {
                    fmt.Printf("%s: %s\\n", fieldType, value)
                }
            }
        }
        
        fmt.Println("---")
    }
}`,
                placeholders: []
            },

            // C# Templates
            {
                name: "Basic Connection (File-based)",
                description: "Initialize KSM with file-based configuration",
                language: "csharp",
                category: "connection",
                code: `using System;
using System.Threading.Tasks;
using SecretsManager;
using SecretsManager.Storage;

public class Program
{
    public static async Task Main(string[] args)
    {
        try
        {
            // Initialize file-based storage
            var storage = new LocalConfigStorage("{{CONFIG_FILE}}");
            await SecretsManagerClient.InitializeStorage(storage, "{{ONE_TIME_TOKEN}}");
            
            // Create SecretsManager options
            var options = new SecretsManagerOptions(storage);
            
            // Verify connection
            var secrets = await SecretsManagerClient.GetSecretsAsync(options);
            Console.WriteLine($"Connected successfully! Found {secrets.Records.Count} secrets.");
            
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Connection failed: {ex.Message}");
        }
    }
}`,
                placeholders: ['CONFIG_FILE', 'ONE_TIME_TOKEN']
            },
            {
                name: "Get All Secrets",
                description: "Retrieve all secrets from the vault",
                language: "csharp",
                category: "retrieval",
                code: `using System;
using System.Threading.Tasks;
using SecretsManager;

public async Task GetAllSecrets(SecretsManagerOptions options)
{
    try
    {
        var secrets = await SecretsManagerClient.GetSecretsAsync(options);
        
        Console.WriteLine($"Found {secrets.Records.Count} secrets");
        
        // Process each secret
        foreach (var record in secrets.Records)
        {
            Console.WriteLine($"Record: {record.Data.Title}");
            Console.WriteLine($"UID: {record.RecordUid}");
            
            // Access specific fields
            foreach (var field in record.Data.Fields)
            {
                var fieldType = field.Type;
                if (field.Value != null && field.Value.Count > 0)
                {
                    var value = field.Value[0];
                    
                    if (fieldType == "password")
                    {
                        Console.WriteLine($"Password: {new string('*', value.Length)}");
                    }
                    else
                    {
                        Console.WriteLine($"{fieldType}: {value}");
                    }
                }
            }
            
            Console.WriteLine("---");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Failed to retrieve secrets: {ex.Message}");
    }
}`,
                placeholders: []
            }
        ];
    }

    public getTemplates(language?: string, category?: string): CodeTemplate[] {
        let filteredTemplates = this.templates;

        if (language) {
            filteredTemplates = filteredTemplates.filter(t => t.language === language);
        }

        if (category) {
            filteredTemplates = filteredTemplates.filter(t => t.category === category);
        }

        return filteredTemplates;
    }

    public getLanguages(): string[] {
        const languages = [...new Set(this.templates.map(t => t.language))];
        return languages.sort();
    }

    public getCategories(language?: string): string[] {
        let templates = this.templates;
        if (language) {
            templates = templates.filter(t => t.language === language);
        }
        const categories = [...new Set(templates.map(t => t.category))];
        return categories.sort();
    }

    public async generateCode(template: CodeTemplate, values: { [key: string]: string }): Promise<string> {
        let code = template.code;

        // Replace placeholders with actual values
        for (const placeholder of template.placeholders) {
            const value = values[placeholder] || `{{${placeholder}}}`;
            code = code.replace(new RegExp(`{{${placeholder}}}`, 'g'), value);
        }

        return code;
    }

    public async showCodeGenerationPicker(): Promise<void> {
        // First, select language
        const languages = this.getLanguages();
        const selectedLanguage = await vscode.window.showQuickPick(
            languages.map(lang => ({
                label: lang.charAt(0).toUpperCase() + lang.slice(1),
                description: `Generate ${lang} code samples`,
                value: lang
            })),
            { placeHolder: 'Select programming language' }
        );

        if (!selectedLanguage) return;

        // Then, select category
        const categories = this.getCategories(selectedLanguage.value);
        const categoryLabels = {
            'connection': 'Connection & Setup',
            'retrieval': 'Secret Retrieval',
            'record': 'Record Management',
            'file': 'File Operations',
            'folder': 'Folder Management'
        };

        const selectedCategory = await vscode.window.showQuickPick(
            categories.map(cat => ({
                label: categoryLabels[cat as keyof typeof categoryLabels] || cat,
                description: `${cat} operations`,
                value: cat
            })),
            { placeHolder: 'Select operation category' }
        );

        if (!selectedCategory) return;

        // Finally, select specific template
        const templates = this.getTemplates(selectedLanguage.value, selectedCategory.value);
        const selectedTemplate = await vscode.window.showQuickPick(
            templates.map(template => ({
                label: template.name,
                description: template.description,
                template: template
            })),
            { placeHolder: 'Select code template' }
        );

        if (!selectedTemplate) return;

        // Collect placeholder values
        const values: { [key: string]: string } = {};
        for (const placeholder of selectedTemplate.template.placeholders) {
            const value = await this.getPlaceholderValue(placeholder);
            if (value === undefined) return; // User cancelled
            values[placeholder] = value;
        }

        // Generate and insert code
        const generatedCode = await this.generateCode(selectedTemplate.template, values);
        
        // Insert into active editor
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            const position = editor.selection.active;
            await editor.edit(editBuilder => {
                editBuilder.insert(position, generatedCode);
            });
        } else {
            // Create new file if no active editor
            const doc = await vscode.workspace.openTextDocument({
                content: generatedCode,
                language: this.getLanguageId(selectedLanguage.value)
            });
            await vscode.window.showTextDocument(doc);
        }
    }

    private async getPlaceholderValue(placeholder: string): Promise<string | undefined> {
        const placeholderLabels = {
            'CONFIG_FILE': 'Configuration file path (e.g., config.json)',
            'ONE_TIME_TOKEN': 'One-time token (e.g., US:YOUR_TOKEN)',
            'BASE64_CONFIG': 'Base64 encoded configuration',
            'SECRET_UID_1': 'First secret UID',
            'SECRET_UID_2': 'Second secret UID',
            'RECORD_TITLE': 'Record title',
            'USERNAME': 'Username',
            'URL': 'URL',
            'NOTES': 'Notes',
            'FOLDER_UID': 'Folder UID',
            'FILE_PATH': 'File path',
            'RECORD_UID': 'Record UID'
        };

        const label = placeholderLabels[placeholder as keyof typeof placeholderLabels] || placeholder;
        
        // Special handling for certain placeholders
        if (placeholder === 'FOLDER_UID' || placeholder === 'SECRET_UID_1' || placeholder === 'SECRET_UID_2' || placeholder === 'RECORD_UID') {
            return await this.selectSecret(placeholder);
        }
        
        return await vscode.window.showInputBox({
            prompt: `Enter ${label}`,
            placeHolder: label
        });
    }

    private async selectSecret(placeholder: string): Promise<string | undefined> {
        if (!this.ksmService.isAuthenticated()) {
            vscode.window.showWarningMessage('Please authenticate with Keeper first');
            return undefined;
        }

        const secrets = this.ksmService.getSecrets();
        const selectedSecret = await vscode.window.showQuickPick(
            secrets.map(s => ({
                label: s.data.title || s.recordUid,
                description: s.recordUid,
                value: s.recordUid
            })),
            { placeHolder: `Select secret for ${placeholder}` }
        );

        return selectedSecret?.value;
    }

    private getLanguageId(language: string): string {
        const languageIds = {
            'python': 'python',
            'javascript': 'javascript',
            'java': 'java',
            'go': 'go',
            'csharp': 'csharp'
        };
        return languageIds[language as keyof typeof languageIds] || 'plaintext';
    }
}