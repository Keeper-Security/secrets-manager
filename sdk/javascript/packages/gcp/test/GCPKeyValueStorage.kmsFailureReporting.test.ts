// loadConfig() decides whether the config file is plaintext or ciphertext by trying to
// JSON.parse it. Encrypting the file afterwards is a consequence of that decision, not part of
// making it, so a KMS failure while encrypting must not be reported as a problem with the file.
//
// These tests use the real filesystem and the real encryptBuffer/decryptBuffer envelope logic
// (only the KMS calls themselves are doubled), because the property under test is which error
// text an operator ends up seeing after a full pass through loadConfig. A test that stubbed
// saveConfig or decryptBuffer wholesale would assert the mock's behaviour, not the SDK's.
jest.mock('@google-cloud/kms', () => ({
    KeyManagementServiceClient: jest.fn().mockImplementation(() => ({
        encrypt: jest.fn(),
        decrypt: jest.fn(),
        getCryptoKey: jest.fn(),
        getPublicKey: jest.fn(),
    })),
}));
jest.mock('../src/GcpKmsClient', () => ({
    GCPKSMClient: jest.fn().mockImplementation(() => ({
        getCryptoClient: jest.fn().mockReturnValue({
            encrypt: jest.fn(),
            decrypt: jest.fn(),
            getCryptoKey: jest.fn(),
            getPublicKey: jest.fn(),
        }),
        getToken: jest.fn().mockResolvedValue('mock-token'),
    })),
}));
jest.mock('../src/Logger', () => ({
    getLogger: jest.fn().mockReturnValue({
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
    }),
}));

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { crc32c as calculate } from '@aws-crypto/crc32c';
import { GCPKeyValueStorage } from '../src/GCPKeyValueStore';
import { GCPKeyConfig } from '../src/GcpKeyConfig';
import { GCPKSMClient } from '../src/GcpKmsClient';
import * as gcpUtils from '../src/utils';
import { Logger } from 'pino';

const KEY_RESOURCE_NAME =
    'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1';

const KMS_FAILURE_MESSAGE =
    'PERMISSION_DENIED: Cloud KMS key version projects/test-project/.../1 is disabled';

// Matches every message loadConfig can produce that blames the file rather than the KMS call.
const BLAMES_THE_FILE = /may contain JSON format problems|JSON format|Invalid header|Failed to parse decrypted config file/;

const silentLogger = { debug() { }, info() { }, warn() { }, error() { } } as unknown as Logger;

function makeStorage(configPath: string) {
    const mockSessionConfig = new GCPKSMClient();
    const gcpKeyConfig = new GCPKeyConfig(KEY_RESOURCE_NAME);
    const storage = new GCPKeyValueStorage(configPath, gcpKeyConfig, mockSessionConfig);
    const cryptoClient = mockSessionConfig.getCryptoClient();

    // Drive keyType/isAsymmetric/encryptionAlgorithm through the real getKeyDetails() via
    // init(), rather than assigning the private fields, so the test enters loadConfig() the
    // same way a caller does.
    (cryptoClient.getCryptoKey as jest.Mock).mockResolvedValue([
        { purpose: 'ENCRYPT_DECRYPT', versionTemplate: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION' } },
    ]);
    // identity-wrap encrypt/decrypt, matching the pattern in
    // GCPKeyValueStorage.atomicWrite.test.ts: exercises the real envelope format without KMS.
    (cryptoClient.encrypt as jest.Mock).mockImplementation(async (input: { plaintext: Buffer }) => {
        const ciphertext = input.plaintext;
        return [{
            ciphertext,
            verifiedPlaintextCrc32c: true,
            ciphertextCrc32c: { value: calculate(ciphertext) },
        }];
    });
    (cryptoClient.decrypt as jest.Mock).mockImplementation(async (input: { ciphertext: Buffer }) => {
        const plaintext = input.ciphertext;
        return [{
            plaintext,
            plaintextCrc32c: { value: calculate(plaintext) },
        }];
    });
    return { storage, cryptoClient };
}

async function captureInitError(storage: GCPKeyValueStorage): Promise<Error> {
    try {
        await storage.init();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
        return err;
    }
    throw new Error('init() resolved but was expected to reject');
}

describe('loadConfig() error reporting when KMS fails (KSM-1460)', () => {
    let tmpDir: string;
    let configPath: string;
    let decryptBufferSpy: jest.SpyInstance;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-failure-reporting-'));
        configPath = path.join(tmpDir, 'config.json');
        // Spied, not stubbed: the real implementation still runs, so the corrupt-file
        // expectations below stay honest while call count is still observable.
        decryptBufferSpy = jest.spyOn(gcpUtils, 'decryptBuffer');
    });

    afterEach(() => {
        decryptBufferSpy.mockRestore();
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    describe('a plaintext config file that cannot be encrypted', () => {
        it('rejects with the KMS error itself, not with a complaint about the file', async () => {
            fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc' }), { mode: 0o600 });
            const { storage, cryptoClient } = makeStorage(configPath);
            (cryptoClient.encrypt as jest.Mock).mockRejectedValue(new Error(KMS_FAILURE_MESSAGE));

            const error = await captureInitError(storage);

            expect(error.message).toBe(KMS_FAILURE_MESSAGE);
            expect(error.message).not.toMatch(BLAMES_THE_FILE);
        });

        it('never tries to decrypt content it already parsed as plaintext JSON', async () => {
            fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc' }), { mode: 0o600 });
            const { storage, cryptoClient } = makeStorage(configPath);
            (cryptoClient.encrypt as jest.Mock).mockRejectedValue(new Error(KMS_FAILURE_MESSAGE));

            await captureInitError(storage);

            expect(decryptBufferSpy).not.toHaveBeenCalled();
            expect(cryptoClient.decrypt).not.toHaveBeenCalled();
        });

        it('leaves the plaintext config file on disk untouched', async () => {
            const originalContent = JSON.stringify({ clientId: 'abc' });
            fs.writeFileSync(configPath, originalContent, { mode: 0o600 });
            const { storage, cryptoClient } = makeStorage(configPath);
            (cryptoClient.encrypt as jest.Mock).mockRejectedValue(new Error(KMS_FAILURE_MESSAGE));

            await captureInitError(storage);

            expect(fs.readFileSync(configPath, 'utf8')).toBe(originalContent);
        });

        it('reports a transient KMS outage distinguishably from a genuinely corrupt file', async () => {
            fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc' }), { mode: 0o600 });
            const { storage: kmsStorage, cryptoClient } = makeStorage(configPath);
            (cryptoClient.encrypt as jest.Mock).mockRejectedValue(new Error(KMS_FAILURE_MESSAGE));
            const kmsError = await captureInitError(kmsStorage);

            const corruptPath = path.join(tmpDir, 'corrupt.json');
            fs.writeFileSync(corruptPath, 'not-json-and-not-ciphertext', { mode: 0o600 });
            const { storage: corruptStorage } = makeStorage(corruptPath);
            const corruptError = await captureInitError(corruptStorage);

            expect(kmsError.message).not.toBe(corruptError.message);
        });
    });

    describe('genuinely unreadable config files still report a file problem', () => {
        it('reports a decryption failure for content that is neither JSON nor a valid envelope', async () => {
            fs.writeFileSync(configPath, 'not-json-and-not-ciphertext', { mode: 0o600 });
            const { storage } = makeStorage(configPath);

            const error = await captureInitError(storage);

            expect(error.message).toBe('Decryption failed : Invalid header');
            expect(decryptBufferSpy).toHaveBeenCalledTimes(1);
        });

        it('reports a parse failure for a valid envelope wrapping a non-JSON payload', async () => {
            const { storage, cryptoClient } = makeStorage(configPath);
            // Build a real envelope around a non-JSON payload using the identity-wrap mock.
            const blob = await gcpUtils.encryptBuffer({
                isAsymmetric: false,
                message: 'NOT-JSON-PAYLOAD',
                cryptoClient,
                keyType: 'ENCRYPT_DECRYPT',
                encryptionAlgorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION',
                keyProperties: new GCPKeyConfig(KEY_RESOURCE_NAME),
                token: null,
            }, silentLogger);
            fs.writeFileSync(configPath, blob, { mode: 0o600 });

            const error = await captureInitError(storage);

            expect(error.message).toBe(`Failed to parse decrypted config file ${configPath}`);
        });
    });

    describe('the plaintext path still works when KMS is healthy', () => {
        it('encrypts a plaintext config file in place and loads its values', async () => {
            fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc' }), { mode: 0o600 });
            const { storage } = makeStorage(configPath);

            await storage.init();

            expect(await storage.getString('clientId')).toBe('abc');
            // The file must no longer be the plaintext it started as.
            expect(fs.readFileSync(configPath, 'utf8')).not.toBe(JSON.stringify({ clientId: 'abc' }));
            expect(await storage.decryptConfig(false)).toContain('"clientId"');
        });
    });
});
