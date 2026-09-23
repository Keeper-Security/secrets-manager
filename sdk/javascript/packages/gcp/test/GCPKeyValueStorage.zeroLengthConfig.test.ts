// A zero-length config file is the classic result of an interrupted write, not a "no config
// yet" state: createConfigFileIfMissing() runs first and only ever creates a file holding a
// real encrypted blob, so 0 bytes can only mean a file that already existed was truncated.
// loadConfig() must refuse to touch it rather than re-encrypt an empty config over the top,
// which would destroy the client id, app key and device private key with no recovery path.
//
// Deliberately does NOT mock `fs` (unlike GCPKeyValueStorage.test.ts, whose blanket
// jest.mock('fs', ...) is hoisted over every test in that file): the property under test is
// real on-disk state - byte length and inode - after a rejected init(). A mocked-fs assertion
// that "writeFile was not called" cannot see the atomic temp-file-then-rename that actually
// replaces the file, so it would pass while the real file was being overwritten.
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

const KEY_RESOURCE_NAME =
    'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1';

// identity-wrap encrypt/decrypt: exercises the real encryptBuffer/decryptBuffer envelope logic
// without a real GCP KMS call, matching the pattern already used in
// GCPKeyValueStorage.atomicWrite.test.ts.
function makeStorage(configPath: string): GCPKeyValueStorage {
    const mockSessionConfig = new GCPKSMClient();
    const gcpKeyConfig = new GCPKeyConfig(KEY_RESOURCE_NAME);
    const storage = new GCPKeyValueStorage(configPath, gcpKeyConfig, mockSessionConfig);
    const cryptoClient = mockSessionConfig.getCryptoClient();
    (cryptoClient.getCryptoKey as jest.Mock).mockResolvedValue([
        { purpose: 'ENCRYPT_DECRYPT', versionTemplate: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION' } },
    ]);
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
    return storage;
}

describe('loadConfig() against a zero-length config file (real fs)', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-zero-length-config-'));
        configPath = path.join(tmpDir, 'config.json');
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('init() rejects instead of treating the truncated file as an empty config', async () => {
        fs.writeFileSync(configPath, '', { mode: 0o600 });
        expect(fs.statSync(configPath).size).toBe(0);

        const storage = makeStorage(configPath);

        await expect(storage.init()).rejects.toThrow(/is empty/);
    });

    it('init() leaves the truncated file byte-for-byte and inode-for-inode untouched', async () => {
        fs.writeFileSync(configPath, '', { mode: 0o600 });
        const inodeBefore = fs.statSync(configPath).ino;

        const storage = makeStorage(configPath);

        await expect(storage.init()).rejects.toThrow(/is empty/);

        // Still recognisably damaged. Re-encrypting an empty config over the top would leave a
        // file that looks valid to every later reader, hiding the fact that data was lost.
        expect(fs.statSync(configPath).size).toBe(0);
        expect(fs.statSync(configPath).ino).toBe(inodeBefore);
        expect(fs.readdirSync(tmpDir)).toEqual(['config.json']);
    });

    it('init() attempts no write at all against a zero-length file', async () => {
        fs.writeFileSync(configPath, '', { mode: 0o600 });

        // Asserting on the write helper rather than only on the resulting bytes catches a
        // regression that writes and then happens to produce 0 bytes again.
        const atomicWrite = require('../src/atomicWrite');
        const spy = jest.spyOn(atomicWrite, 'writeFileAtomicSync');
        const storage = makeStorage(configPath);

        await expect(storage.init()).rejects.toThrow(/is empty/);

        expect(spy).not.toHaveBeenCalled();
        spy.mockRestore();
    });

    it('names the offending config file in the error so the caller can recover it', async () => {
        fs.writeFileSync(configPath, '', { mode: 0o600 });

        const storage = makeStorage(configPath);

        await expect(storage.init()).rejects.toThrow(configPath);
    });

    it('still creates and loads a config when the file is genuinely missing', async () => {
        expect(fs.existsSync(configPath)).toBe(false);

        const storage = makeStorage(configPath);

        await expect(storage.init()).resolves.toBe(storage);
        expect(fs.statSync(configPath).size).toBeGreaterThan(0);
        await expect(storage.isEmpty()).resolves.toBe(true);
    });

    it('still loads an existing encrypted config', async () => {
        const seed = makeStorage(configPath);
        await seed.init();
        await seed.saveString('clientId', 'abc');
        const encryptedSize = fs.statSync(configPath).size;
        expect(encryptedSize).toBeGreaterThan(0);

        const storage = makeStorage(configPath);

        await expect(storage.init()).resolves.toBe(storage);
        await expect(storage.getString('clientId')).resolves.toBe('abc');
    });

    it('still encrypts a non-empty plaintext JSON config in place', async () => {
        fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc' }), { mode: 0o600 });

        const storage = makeStorage(configPath);

        await expect(storage.init()).resolves.toBe(storage);
        await expect(storage.getString('clientId')).resolves.toBe('abc');
        expect(fs.readFileSync(configPath, 'utf8')).not.toBe(JSON.stringify({ clientId: 'abc' }));
    });
});

// decryptConfig() (the plaintext-export path used for migration and backup, per KSM-1486) has
// its own, independent fs.readFile call and its own zero-length check. It does not call
// loadConfig() or init(), so the KSM-1455 fix above does not cover it. Before this fix,
// a zero-length file logged a warning and resolved to "", indistinguishable from a config
// that legitimately decrypted to nothing - the caller had no way to detect the corruption.
describe('decryptConfig() against a zero-length config file (real fs)', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-zero-length-decrypt-'));
        configPath = path.join(tmpDir, 'config.json');
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('rejects instead of resolving to an empty string', async () => {
        fs.writeFileSync(configPath, '', { mode: 0o600 });
        expect(fs.statSync(configPath).size).toBe(0);

        const storage = makeStorage(configPath);

        await expect(storage.decryptConfig(false)).rejects.toThrow(/is empty/);
    });

    it('names the offending config file in the error so the caller can recover it', async () => {
        fs.writeFileSync(configPath, '', { mode: 0o600 });

        const storage = makeStorage(configPath);

        await expect(storage.decryptConfig(false)).rejects.toThrow(configPath);
    });

    it('leaves the file untouched even when autosave is requested', async () => {
        fs.writeFileSync(configPath, '', { mode: 0o600 });

        const storage = makeStorage(configPath);

        await expect(storage.decryptConfig(true)).rejects.toThrow(/is empty/);

        // autosave writes the decrypted plaintext back through the same file; a config that
        // never made it past the zero-length check must never reach that write.
        expect(fs.statSync(configPath).size).toBe(0);
    });

    it('still decrypts a genuine non-empty config', async () => {
        const storage = makeStorage(configPath);
        await storage.init();
        await storage.saveString('clientId', 'abc');

        const decrypted = await storage.decryptConfig(false);

        expect(JSON.parse(decrypted)).toMatchObject({ clientId: 'abc' });
    });
});
