// KSM-1515: loadConfig() parses the config file and never checks the type of the result.
// JSON.parse() succeeds for null, 0, false, "", [], [1,2,3], 123, and a quoted string, none of
// which is the declared Record<string, string>. Each shape took a different silently wrong path:
// falsy scalars left the file in plaintext while claiming encryption started; arrays made the
// no-op-save skip fire on every later save, persisting nothing; primitives got written to disk
// encrypted, then threw a native TypeError on the next set(). This file empirically reproduces
// all three groups against the real module, at both parse sites (plaintext and decrypted).
//
// Deliberately does NOT mock `fs` (unlike GCPKeyValueStorage.test.ts): the property under test
// is real on-disk state, exact byte content before and after, which a mocked fs.readFile can't
// observe.
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
// Not the standard shared mock: info/debug/error stay real jest.fn()s (not no-ops) so TEST 1 can
// assert on exactly which log lines fired, not just that init() rejected.
const mockLogger = {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
};
jest.mock('../src/Logger', () => ({
    getLogger: jest.fn(() => mockLogger),
}));

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { crc32c as calculate } from '@aws-crypto/crc32c';
import { GCPKeyValueStorage } from '../src/GCPKeyValueStore';
import { GCPKeyConfig } from '../src/GcpKeyConfig';
import { GCPKSMClient } from '../src/GcpKmsClient';
import { GCPKeyValueStorageError } from '../src/error';
import { encryptBuffer } from '../src/utils';
import { Logger } from 'pino';

const KEY_RESOURCE_NAME =
    'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1';

// identity-wrap encrypt/decrypt, matching the pattern already used throughout this package's
// test suite (see GCPKeyValueStorage.deletedConfigFile.test.ts).
function makeStorage(configPath: string): { storage: GCPKeyValueStorage; cryptoClient: ReturnType<GCPKSMClient['getCryptoClient']> } {
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
    return { storage, cryptoClient };
}

// Builds a real encrypted blob (via the same identity-wrap crypto client a makeStorage()
// instance already uses) holding an arbitrary plaintext payload, for TEST 5 and the corrupt-file
// regression check, neither of which can be exercised through the plaintext parse path.
async function encryptPayload(cryptoClient: ReturnType<GCPKSMClient['getCryptoClient']>, message: string): Promise<Buffer> {
    return encryptBuffer({
        isAsymmetric: false,
        message,
        keyType: 'ENCRYPT_DECRYPT',
        cryptoClient,
        encryptionAlgorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION',
        keyProperties: new GCPKeyConfig(KEY_RESOURCE_NAME),
        token: null,
    }, mockLogger as unknown as Logger);
}

const rejectionOf = async (promise: Promise<unknown>): Promise<unknown> =>
    promise.then(() => null, (err) => err);

describe('GCPKeyValueStorage config shape validation (KSM-1515)', () => {
    let tmpDir: string;
    let configPath: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-config-shape-'));
        configPath = path.join(tmpDir, 'config.json');
        jest.clearAllMocks();
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    describe('TEST 1: falsy scalars must be refused', () => {
        it.each([
            ['null', 'null'],
            ['0', '0'],
            ['false', 'false'],
            ['an empty string ("")', '""'],
        ])('init() rejects when the whole file content is %s', async (_label, content) => {
            fs.writeFileSync(configPath, content);
            const contentsBefore = fs.readFileSync(configPath);
            const { storage } = makeStorage(configPath);

            const rejection = await rejectionOf(storage.init());

            expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
            expect((rejection as Error).message).toContain(configPath);
            // Byte-for-byte unchanged is the assertion that matters: a fix must not "help" by
            // encrypting the bad content instead of refusing it.
            expect(fs.readFileSync(configPath)).toEqual(contentsBefore);
            // The misleading half of the current behavior: this line must not fire for content
            // that was never actually a valid configuration to begin with.
            expect(mockLogger.info).not.toHaveBeenCalledWith(
                expect.stringContaining('not encrypted, starting encryption')
            );
        });
    });

    describe('TEST 2: arrays must be refused', () => {
        it.each([
            ['an empty array', '[]'],
            ['a non-empty array', '[1,2,3]'],
        ])('init() rejects for %s, before any write', async (_label, content) => {
            fs.writeFileSync(configPath, content);
            const contentsBefore = fs.readFileSync(configPath);
            const { storage } = makeStorage(configPath);

            const rejection = await rejectionOf(storage.init());

            expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
            expect(fs.readFileSync(configPath)).toEqual(contentsBefore);
        });
        // The ticket also asks that a later saveString() never resolve while persisting
        // nothing, "if a build still reaches" it. This fix closes the gap at its source, inside
        // loadConfig(), so init() itself already rejects and that call site is never reached;
        // the sibling KSM-1516 PR (not yet merged, adds an init() guard to every other public
        // method) is what additionally guarantees a bare saveString() rejects too, on a general
        // basis unrelated to any particular parse result. The two are complementary, not
        // duplicated: this ticket's own fix is complete on its own for the path it names.
    });

    describe('TEST 3: primitives must be refused before the file is touched', () => {
        it.each([
            ['a bare number', '123'],
            ['a quoted string', '"a string"'],
        ])('init() rejects for %s, and the file is untouched, not overwritten first', async (_label, content) => {
            fs.writeFileSync(configPath, content);
            const contentsBefore = fs.readFileSync(configPath);
            const { storage } = makeStorage(configPath);

            const rejection = await rejectionOf(storage.init());

            // The assertion that matters: today's actual bug overwrites the file with the
            // encrypted primitive FIRST, and only a later set() throws, so file-unchanged is
            // what a partial fix (one that only improves the later TypeError) would still fail.
            expect(fs.readFileSync(configPath)).toEqual(contentsBefore);
            expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
            expect(rejection).not.toBeInstanceOf(TypeError);
        });
    });

    describe('TEST 4: the happy path must still work', () => {
        it('a normal plaintext config of flat string values is still encrypted on first init(), and still loads in a second process', async () => {
            fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc', appKey: 'xyz' }));
            const { storage } = makeStorage(configPath);

            await storage.init();
            expect(await storage.getString('clientId')).toBe('abc');

            const { storage: reopened } = makeStorage(configPath);
            await reopened.init();
            expect(await reopened.getString('clientId')).toBe('abc');
            expect(await reopened.getString('appKey')).toBe('xyz');
        });

        it('a normal encrypted config still loads', async () => {
            const { storage: seed } = makeStorage(configPath);
            await seed.init();
            await seed.saveString('clientId', 'abc');

            const { storage: reopened } = makeStorage(configPath);
            await reopened.init();
            expect(await reopened.getString('clientId')).toBe('abc');
        });

        it('an empty JSON object is still accepted, so a fresh first run still bootstraps', async () => {
            expect(fs.existsSync(configPath)).toBe(false);
            const { storage } = makeStorage(configPath);

            await expect(storage.init()).resolves.toBe(storage);
            expect(await storage.isEmpty()).toBe(true);
        });

        it('an object with a non-string value (a number) is explicitly rejected, not silently coerced or dropped', async () => {
            fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc', retryCount: 5 }));
            const contentsBefore = fs.readFileSync(configPath);
            const { storage } = makeStorage(configPath);

            await expect(storage.init()).rejects.toBeInstanceOf(GCPKeyValueStorageError);
            expect(fs.readFileSync(configPath)).toEqual(contentsBefore);
        });

        it('an object with a nested object value is explicitly rejected the same way', async () => {
            fs.writeFileSync(configPath, JSON.stringify({ clientId: 'abc', nested: { a: 1 } }));
            const contentsBefore = fs.readFileSync(configPath);
            const { storage } = makeStorage(configPath);

            await expect(storage.init()).rejects.toBeInstanceOf(GCPKeyValueStorageError);
            expect(fs.readFileSync(configPath)).toEqual(contentsBefore);
        });
    });

    describe('TEST 5: the decryption path has the same gap, and is the half most likely to be missed', () => {
        it.each([
            ['null', 'null'],
            ['0', '0'],
            ['an empty array', '[]'],
            ['a bare number', '123'],
        ])('init() rejects when the DECRYPTED content is %s', async (_label, decryptedPayload) => {
            const { storage, cryptoClient } = makeStorage(configPath);
            const blob = await encryptPayload(cryptoClient, decryptedPayload);
            fs.writeFileSync(configPath, blob);
            const contentsBefore = fs.readFileSync(configPath);

            const rejection = await rejectionOf(storage.init());

            expect(rejection).toBeInstanceOf(GCPKeyValueStorageError);
            expect((rejection as Error).message).toContain(configPath);
            expect(fs.readFileSync(configPath)).toEqual(contentsBefore);
        });
    });

    describe('regression checks', () => {
        it('KSM-1455: a zero-length file is still refused with the empty-file message, not the new shape message', async () => {
            fs.writeFileSync(configPath, '');
            const { storage } = makeStorage(configPath);

            await expect(storage.init()).rejects.toThrow(/is empty/);
        });

        it('a truly corrupt file (decryptable, but the decrypted content is not JSON at all) still produces the existing corruption error, not the new shape error', async () => {
            // Not "... may contain JSON format problems": that check sits right after this
            // block, but the inner catch immediately below always throws its own error first,
            // so the later check is unreachable dead code, pre-existing and unrelated to this
            // fix (confirmed by this test failing with the OTHER message before this correction,
            // against code this PR does not touch).
            const { storage, cryptoClient } = makeStorage(configPath);
            const blob = await encryptPayload(cryptoClient, 'not valid json {{{');
            fs.writeFileSync(configPath, blob);

            const rejection = await rejectionOf(storage.init());

            expect((rejection as Error).message).toMatch(/Failed to parse decrypted config file/);
            expect((rejection as Error).message).not.toMatch(/is not a valid configuration object/);
        });
    });
});
