// KSM-1516: every public method used to work before init() ever ran. Against a real populated
// config, isEmpty() reported true, contains()/getString() reported nothing, and a pre-init
// saveString()/saveStorage() resolved successfully and overwrote the file, destroying the
// client id, app key and device private key with no recovery path. The guard under test here
// (GCPKeyValueStore.ts's private `initialized` flag, checked by every public method except
// init() itself) is what makes each of those calls reject instead.
//
// Deliberately does NOT mock `fs` (unlike GCPKeyValueStorage.test.ts): several tests here need
// a real encrypted config file on disk, written by one storage instance and then read back
// (or deliberately left untouched) by a second, never-initialized instance pointed at the same
// path, and a mocked-fs assertion can't see whether the real bytes on disk actually changed.
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
import { GCPKeyValueStorageError } from '../src/error';

const KEY_RESOURCE_NAME =
    'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1';

// identity-wrap encrypt/decrypt, matching the pattern already used in
// GCPKeyValueStorage.atomicWrite.test.ts and .zeroLengthConfig.test.ts: exercises the real
// encryptBuffer/decryptBuffer envelope logic without a real GCP KMS call. Unlike those two
// files, this helper does NOT poke `initialized` and DOES mock getCryptoKey, since most tests
// here are specifically about the real init() sequence, not about isolating some other method
// from it.
function makeStorage(configPath: string): { storage: GCPKeyValueStorage; mockSessionConfig: GCPKSMClient } {
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
    return { storage, mockSessionConfig };
}

// Seeds a real, populated, encrypted config file at configPath via a throwaway, properly
// initialized instance, matching the exact shape the ticket's own repro seeds (clientId,
// appKey, privateKey). Every test below points a SEPARATE, never-initialized instance at the
// same path, so a test's own storage instance never touches this one's in-memory state.
async function seedConfig(configPath: string): Promise<void> {
    const { storage } = makeStorage(configPath);
    await storage.init();
    await storage.saveString('clientId', 'REAL-CLIENT-ID');
    await storage.saveString('appKey', 'REAL-APP-KEY');
    await storage.saveString('privateKey', 'REAL-PRIVATE-KEY');
}

// Every public method other than init(), invoked the way a consumer actually calls it. Table-
// driven so a fifteenth method added later has to be added here too, rather than silently
// shipping unguarded.
const GUARDED_METHOD_CALLS: Array<[string, (storage: GCPKeyValueStorage) => Promise<unknown>]> = [
    ['getString', (storage) => storage.getString('clientId')],
    ['saveString', (storage) => storage.saveString('clientId', 'ATTACKER-CLIENT-ID')],
    ['getBytes', (storage) => storage.getBytes('clientId')],
    ['saveBytes', (storage) => storage.saveBytes('clientId', new Uint8Array([1, 2, 3]))],
    ['getObject', (storage) => storage.getObject!('clientId')],
    ['saveObject', (storage) => storage.saveObject!('clientId', { a: 1 })],
    ['delete', (storage) => storage.delete('clientId')],
    ['deleteAll', (storage) => storage.deleteAll()],
    ['contains', (storage) => storage.contains('clientId')],
    ['isEmpty', (storage) => storage.isEmpty()],
    ['readStorage', (storage) => storage.readStorage()],
    ['saveStorage', (storage) => storage.saveStorage({ clientId: 'ATTACKER-CLIENT-ID' })],
    ['decryptConfig', (storage) => storage.decryptConfig(false)],
    ['changeKey', (storage) => storage.changeKey(new GCPKeyConfig(KEY_RESOURCE_NAME))],
];

describe('GCPKeyValueStorage init guard (KSM-1516)', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-init-guard-'));
        configPath = path.join(tmpDir, 'config.json');
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    describe('every method rejects on a never-initialized instance, against a real populated config', () => {
        it.each(GUARDED_METHOD_CALLS)('%s rejects with a named, typed error', async (_name, invoke) => {
            await seedConfig(configPath);
            const contentsBefore = fs.readFileSync(configPath);
            const { storage } = makeStorage(configPath);

            const rejection = await invoke(storage).then(
                () => null,
                (err) => err
            );

            expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
            expect((rejection as Error).message).toMatch(/init\(\)/);
            // The assertion that matters: nothing was read or written on the real file.
            expect(fs.readFileSync(configPath)).toEqual(contentsBefore);
        });
    });

    it('does not fetch a KMS token or call encrypt/decrypt before the guard rejects', async () => {
        // The guard is each method's own first line, before this.keyType is ever read, so no
        // key-purpose branch (symmetric, asymmetric, or raw) is reachable pre-init at all; the
        // meaningful assertion is simply that no KMS-facing call happens, regardless of which
        // purpose the caller would eventually use.
        await seedConfig(configPath);
        const { storage, mockSessionConfig } = makeStorage(configPath);
        const cryptoClient = mockSessionConfig.getCryptoClient();

        await expect(storage.saveString('clientId', 'ATTACKER-CLIENT-ID')).rejects.toBeInstanceOf(
            GCPKeyValueStorageError
        );

        expect(mockSessionConfig.getToken).not.toHaveBeenCalled();
        expect(cryptoClient.encrypt).not.toHaveBeenCalled();
        expect(cryptoClient.decrypt).not.toHaveBeenCalled();
    });

    describe('the isEmpty()-before-init() pattern the README invites', () => {
        it('now rejects instead of falsely reporting an empty, rebindable config', async () => {
            await seedConfig(configPath);
            const contentsBefore = fs.readFileSync(configPath);
            const { storage } = makeStorage(configPath);

            await expect(storage.isEmpty()).rejects.toBeInstanceOf(GCPKeyValueStorageError);

            expect(fs.readFileSync(configPath)).toEqual(contentsBefore);
        });

        it('once corrected to call init() first, reports the config as populated and every credential survives', async () => {
            await seedConfig(configPath);
            const { storage } = makeStorage(configPath);

            await storage.init();

            expect(await storage.isEmpty()).toBe(false);
            expect(await storage.getString('clientId')).toBe('REAL-CLIENT-ID');
            expect(await storage.getString('appKey')).toBe('REAL-APP-KEY');
            expect(await storage.getString('privateKey')).toBe('REAL-PRIVATE-KEY');
        });
    });

    describe('a failed init() leaves the instance exactly as unusable as one that was never initialized', () => {
        it('rejects every method the same way afterward, not just the four the ticket names first', async () => {
            await seedConfig(configPath);
            const { storage, mockSessionConfig } = makeStorage(configPath);
            const cryptoClient = mockSessionConfig.getCryptoClient();
            (cryptoClient.getCryptoKey as jest.Mock).mockRejectedValueOnce(
                new Error('PERMISSION_DENIED: the caller does not have permission')
            );

            await expect(storage.init()).rejects.toThrow('PERMISSION_DENIED');

            // A flag set at the START of init() would pass every check below anyway; only
            // setting it at the END, after both init() steps succeed, makes this fail correctly.
            for (const [, invoke] of GUARDED_METHOD_CALLS) {
                await expect(invoke(storage)).rejects.toBeInstanceOf(GCPKeyValueStorageError);
            }
        });
    });

    describe('repeated and concurrent init()', () => {
        it('a second init() call on an already-initialized instance still works', async () => {
            const { storage } = makeStorage(configPath);

            await storage.init();
            await storage.init();

            expect(await storage.isEmpty()).toBe(true);
        });

        it('two concurrent init() calls, neither awaited before the other starts, both leave the instance fully usable', async () => {
            const { storage } = makeStorage(configPath);

            const first = storage.init();
            const second = storage.init();
            await Promise.all([first, second]);

            await storage.saveString('clientId', 'REAL-CLIENT-ID');
            expect(await storage.getString('clientId')).toBe('REAL-CLIENT-ID');
        });
    });

    describe('regression: changeKey() self-init still works for its real purpose', () => {
        it('still self-initializes when the in-memory config is empty on an ALREADY-initialized instance (post deleteAll())', async () => {
            await seedConfig(configPath);
            const { storage } = makeStorage(configPath);
            await storage.init();
            await storage.deleteAll();

            const newKeyConfig = new GCPKeyConfig(KEY_RESOURCE_NAME);
            await expect(storage.changeKey(newKeyConfig)).resolves.toBe(true);
        });

        it('no longer self-initializes as an implicit bootstrap on a never-initialized instance', async () => {
            await seedConfig(configPath);
            const { storage } = makeStorage(configPath);

            await expect(storage.changeKey(new GCPKeyConfig(KEY_RESOURCE_NAME))).rejects.toBeInstanceOf(
                GCPKeyValueStorageError
            );
        });
    });
});
