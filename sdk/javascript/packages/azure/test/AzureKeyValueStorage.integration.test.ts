import { AzureKeyValueStorage } from '../src/AzureKeyValueStorage';
import { AzureSessionConfig } from '../src/AzureSessionConfig';
import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';

// Intentionally not mocking @azure/identity or @azure/keyvault-keys: this file
// talks to real Azure AD + a real Key Vault key.

const { AZURE_TEST_TENANT_ID: tenantId, AZURE_TEST_CLIENT_ID: clientId,
        AZURE_TEST_CLIENT_SECRET: clientSecret, AZURE_TEST_KEY_ID: keyId } = process.env;
const hasCreds = Boolean(tenantId && clientId && clientSecret && keyId);
const maybeDescribe = hasCreds ? describe : describe.skip;

maybeDescribe('AzureKeyValueStorage integration (real Azure Key Vault)', () => {
    let configPath: string;

    beforeEach(() => {
        configPath = path.join(os.tmpdir(), `ksm-azure-it-${Date.now()}-${Math.random()}.json`);
    });

    afterEach(async () => {
        await fs.rm(configPath, { force: true });
    });

    it('authenticates via ClientSecretCredential and round-trips a value', async () => {
        const sessionConfig = new AzureSessionConfig(tenantId!, clientId!, clientSecret!);
        const storage = await new AzureKeyValueStorage(keyId!, configPath, sessionConfig, null).init();

        await storage.saveString('smoke-test-key', 'smoke-test-value');
        expect(await storage.getString('smoke-test-key')).toBe('smoke-test-value');
    });

    it('authenticates via DefaultAzureCredential fallback and round-trips a value', async () => {
        // A truthy AzureSessionConfig with empty fields — not null — is what actually
        // reaches the DefaultAzureCredential branch (see AzureKeyValueStorage.ts:71-81:
        // passing null skips the outer `if` entirely and leaves azureCredentials undefined).
        const emptySessionConfig = new AzureSessionConfig('', '', '');
        const prevEnv = {
            AZURE_TENANT_ID: process.env.AZURE_TENANT_ID,
            AZURE_CLIENT_ID: process.env.AZURE_CLIENT_ID,
            AZURE_CLIENT_SECRET: process.env.AZURE_CLIENT_SECRET,
        };
        process.env.AZURE_TENANT_ID = tenantId;
        process.env.AZURE_CLIENT_ID = clientId;
        process.env.AZURE_CLIENT_SECRET = clientSecret;

        try {
            const storage = await new AzureKeyValueStorage(keyId!, configPath, emptySessionConfig, null).init();
            await storage.saveString('smoke-test-key', 'smoke-test-value-default-cred');
            expect(await storage.getString('smoke-test-key')).toBe('smoke-test-value-default-cred');
        } finally {
            for (const [k, v] of Object.entries(prevEnv)) {
                if (v === undefined) delete process.env[k]; else process.env[k] = v;
            }
        }
    });
});
