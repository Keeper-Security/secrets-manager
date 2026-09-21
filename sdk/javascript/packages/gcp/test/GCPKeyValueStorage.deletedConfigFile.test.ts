// Deliberately does NOT mock `fs` (unlike GCPKeyValueStorage.test.ts). The regression here is a
// config file that disappears from the filesystem while the process keeps running, so the test
// needs a real file it can really delete, and real encrypted bytes it can really read back and
// decrypt. A mocked fs can only prove which calls were made, not that the surviving on-disk
// bytes still hold the caller's data.
//
// The assertion that matters is the content one, not the existence one: a fix that only reorders
// createConfigFileIfMissing() ahead of the no-changes-detected early return makes the file exist
// again, but holding that method's `{}` placeholder instead of the real config. That is still
// silent data loss, and only decrypting the recreated file catches it.
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

// identity-wrap encrypt/decrypt: exercises the real encryptBuffer/decryptBuffer envelope logic
// without a real GCP KMS call, matching the pattern used in GCPKeyValueStorage.atomicWrite.test.ts.
function makeStorage(configPath: string): GCPKeyValueStorage {
    const mockSessionConfig = new GCPKSMClient();
    const gcpKeyConfig = new GCPKeyConfig(KEY_RESOURCE_NAME);
    const storage = new GCPKeyValueStorage(configPath, gcpKeyConfig, mockSessionConfig);
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
    (cryptoClient.getCryptoKey as jest.Mock).mockResolvedValue([
        { purpose: 'ENCRYPT_DECRYPT', versionTemplate: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION' } },
    ]);
    (storage as any).keyType = 'ENCRYPT_DECRYPT';
    (storage as any).isAsymmetric = false;
    (storage as any).encryptionAlgorithm = 'GOOGLE_SYMMETRIC_ENCRYPTION';
    return storage;
}

async function readConfigFromDisk(storage: GCPKeyValueStorage): Promise<Record<string, string>> {
    return JSON.parse(await storage.decryptConfig(false));
}

describe('saveConfig() when the config file is deleted underneath a running process', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-deleted-config-'));
        configPath = path.join(tmpDir, 'config.json');
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('saveString() rewrites the real config, not an empty placeholder, when the file is gone', async () => {
        const storage = makeStorage(configPath);
        await storage.saveString('clientId', 'ABC');
        expect(await readConfigFromDisk(storage)).toEqual({ clientId: 'ABC' });

        fs.rmSync(configPath);
        expect(fs.existsSync(configPath)).toBe(false);

        // Same value as the last save, so the in-memory hash still matches lastSavedConfigHash
        // and the pre-fix early return fires before the file is ever looked at.
        await storage.saveString('clientId', 'ABC');

        expect(fs.existsSync(configPath)).toBe(true);
        expect(await readConfigFromDisk(storage)).toEqual({ clientId: 'ABC' });
        expect(fileMode(configPath)).toBe(0o600);
    });

    it('saveStorage() rewrites the real config, not an empty placeholder, when the file is gone', async () => {
        const storage = makeStorage(configPath);
        await storage.saveStorage({ clientId: 'ABC', appKey: 'XYZ' });
        expect(await readConfigFromDisk(storage)).toEqual({ clientId: 'ABC', appKey: 'XYZ' });

        fs.rmSync(configPath);
        expect(fs.existsSync(configPath)).toBe(false);

        await storage.saveStorage({ clientId: 'ABC', appKey: 'XYZ' });

        expect(fs.existsSync(configPath)).toBe(true);
        expect(await readConfigFromDisk(storage)).toEqual({ clientId: 'ABC', appKey: 'XYZ' });
    });

    // The ticket's actual failure mode: saveString() resolves, the caller believes the value is
    // persisted, and the loss only surfaces when a new process loads the config file.
    it('a fresh instance loads the real config after a resolved save over a deleted file', async () => {
        const storage = makeStorage(configPath);
        await storage.saveString('clientId', 'ABC');

        fs.rmSync(configPath);
        await storage.saveString('clientId', 'ABC');

        const restarted = await makeStorage(configPath).init();
        expect(await restarted.getString('clientId')).toBe('ABC');
    });

    // Pins the one behavior change beyond the bug itself: when the existence of the config file
    // cannot be determined at all, an unchanged save must report the failure rather than resolve
    // on the assumption that the file is still there. Uses ENOTDIR rather than a chmod-based
    // EACCES so the test behaves the same for an unprivileged user and for root.
    it('rejects instead of skipping when the config file path cannot be checked', async () => {
        const subDir = path.join(tmpDir, 'sub');
        fs.mkdirSync(subDir);
        const storage = makeStorage(path.join(subDir, 'config.json'));
        await storage.saveString('clientId', 'ABC');

        // Replace the parent directory with a regular file, so resolving the config path fails
        // with ENOTDIR instead of the ENOENT that means "genuinely missing".
        fs.rmSync(subDir, { recursive: true });
        fs.writeFileSync(subDir, 'not a directory');

        await expect(storage.saveString('clientId', 'ABC')).rejects.toMatchObject({
            code: 'ENOTDIR',
        });
    });

    it('still skips the write when nothing changed and the config file is present', async () => {
        const storage = makeStorage(configPath);
        await storage.saveString('clientId', 'ABC');

        const atomicWrite = require('../src/atomicWrite');
        const spy = jest.spyOn(atomicWrite, 'writeFileAtomicSync');
        try {
            await storage.saveString('clientId', 'ABC');
            expect(spy).not.toHaveBeenCalled();
        } finally {
            spy.mockRestore();
        }
    });
});
