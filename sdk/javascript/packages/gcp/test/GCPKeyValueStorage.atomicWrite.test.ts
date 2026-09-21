// Deliberately does NOT mock `fs` (unlike GCPKeyValueStorage.test.ts). These tests assert
// real on-disk file/inode state and real writeFileAtomicSync call counts for properties a
// mocked-fs assertion can't catch: a stale reader fd surviving the "fix", decryptConfig's
// autosave write having zero real coverage, saveConfig's own write never being checked in
// isolation, createConfigFileIfMissing's second (encrypted) write silently falling back to a
// plain write with no test noticing, and the temp file landing at the wrong mode under a
// umask that strips owner bits.
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

function fileMode(filePath: string): number {
    return fs.statSync(filePath).mode & 0o777;
}

function makeStorage(configPath: string): { storage: GCPKeyValueStorage; mockSessionConfig: GCPKSMClient } {
    const mockSessionConfig = new GCPKSMClient();
    const gcpKeyConfig = new GCPKeyConfig(KEY_RESOURCE_NAME);
    const storage = new GCPKeyValueStorage(configPath, gcpKeyConfig, mockSessionConfig);
    // identity-wrap encrypt/decrypt: exercises the real encryptBuffer/decryptBuffer envelope
    // logic without a real GCP KMS call, matching the pattern already used in
    // GCPKeyValueStorage.test.ts's 'saveConfig() writes the config with a restrictive file mode'.
    const cryptoClient = mockSessionConfig.getCryptoClient();
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
    (storage as any).keyType = 'ENCRYPT_DECRYPT';
    (storage as any).isAsymmetric = false;
    (storage as any).encryptionAlgorithm = 'GOOGLE_SYMMETRIC_ENCRYPTION';
    return { storage, mockSessionConfig };
}

describe('GCPKeyValueStorage config file writes (real fs)', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-atomic-write-'));
        configPath = path.join(tmpDir, 'config.json');
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    describe('writeSecureConfigFile() helper', () => {
        it('does not leave a reader fd opened against the old (0644) file able to read the rewritten secret', async () => {
            fs.writeFileSync(configPath, 'SECRET-OLD', { mode: 0o644 });
            const oldFd = fs.openSync(configPath, 'r');
            const inodeBefore = fs.fstatSync(oldFd).ino;

            const { storage } = makeStorage(configPath);
            await (storage as any).writeSecureConfigFile(configPath, 'SECRET-NEW');

            const inodeAfter = fs.statSync(configPath).ino;
            expect(inodeAfter).not.toBe(inodeBefore);

            const buf = Buffer.alloc(64);
            const n = fs.readSync(oldFd, buf, 0, 64, 0);
            fs.closeSync(oldFd);
            expect(buf.slice(0, n).toString()).toBe('SECRET-OLD');
        });
    });

    describe('createConfigFileIfMissing()', () => {
        it('creates a real, readable config file when none exists yet', async () => {
            expect(fs.existsSync(configPath)).toBe(false);

            const { storage } = makeStorage(configPath);
            await (storage as any).createConfigFileIfMissing();

            expect(fs.existsSync(configPath)).toBe(true);
            expect(fileMode(configPath)).toBe(0o600);
            const decrypted = await storage.decryptConfig(false);
            expect(decrypted).toBe('{}');
        });
    });

    describe('decryptConfig(autosave=true)', () => {
        it('writes the decrypted plaintext at mode 0600, even onto a pre-existing 0644 file', async () => {
            fs.writeFileSync(configPath, '', { mode: 0o644 });
            const { storage } = makeStorage(configPath);
            // Populate a real encrypted config first, using the same identity-wrap crypto mock,
            // then re-loosen the mode to simulate a file left over from an older SDK version.
            await (storage as any).saveConfig({ clientId: 'abc' });
            fs.chmodSync(configPath, 0o644);
            expect(fileMode(configPath)).toBe(0o644);

            await storage.decryptConfig(true);

            expect(fileMode(configPath)).toBe(0o600);
        });
    });

    describe('saveConfig()', () => {
        it('corrects a pre-existing 0644 config file to 0600 on an ordinary save', async () => {
            fs.writeFileSync(configPath, '', { mode: 0o644 });
            const { storage } = makeStorage(configPath);
            expect(fileMode(configPath)).toBe(0o644);

            await (storage as any).saveConfig({ clientId: 'abc' });

            expect(fileMode(configPath)).toBe(0o600);
        });
    });

    describe('createConfigFileIfMissing() call sites', () => {
        it('routes both the placeholder write and the encrypted write through writeFileAtomicSync', async () => {
            const atomicWrite = require('../src/atomicWrite');
            const spy = jest.spyOn(atomicWrite, 'writeFileAtomicSync');
            const { storage } = makeStorage(configPath);

            await (storage as any).createConfigFileIfMissing();

            expect(spy).toHaveBeenCalledTimes(2);
            expect(spy.mock.calls[0][0]).toBe(configPath);
            expect(spy.mock.calls[0][1]).toEqual(Buffer.from('{}'));
            expect(spy.mock.calls[1][0]).toBe(configPath);
            spy.mockRestore();
        });
    });

    describe('writeFileAtomicSync() under a pathological umask', () => {
        it('still lands at exactly 0600 even under an owner-stripping umask', async () => {
            const originalUmask = process.umask(0o700);
            try {
                const { storage } = makeStorage(configPath);
                await (storage as any).writeSecureConfigFile(configPath, 'SECRET');
                expect(fileMode(configPath)).toBe(0o600);
            } finally {
                process.umask(originalUmask);
            }
        });
    });
});
