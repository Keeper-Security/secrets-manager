// Windows has no fs.constants.O_NOFOLLOW and no process.getuid. readConfigFileStrict() therefore
// opens the config path with plain O_RDONLY there, which follows a symlink, so it checks with
// lstat first. The Linux jobs run the symlink tests in GCPKeyValueStorage.symlinkProtection.test.ts
// through the O_NOFOLLOW branch.
//
// This file reloads the module with both missing, so the lstat branch also runs on Linux and
// macOS. It proves the branch logic only. The Windows CI job proves the filesystem behavior.
//
// `fs` is not mocked for the test's own calls: the symlink and target are real files, so what
// the storage does with them is observable on disk.
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

const KEY_RESOURCE_NAME =
    'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1';

type Loaded = {
    GCPKeyValueStorage: typeof import('../src/GCPKeyValueStore').GCPKeyValueStorage;
    GCPKeyConfig: typeof import('../src/GcpKeyConfig').GCPKeyConfig;
    GCPKSMClient: typeof import('../src/GcpKmsClient').GCPKSMClient;
    GCPKeyValueStorageError: typeof import('../src/error').GCPKeyValueStorageError;
};

// fs.constants.O_NOFOLLOW is non-configurable, so it cannot be deleted from the real object.
// The module under test gets a copy of `fs` without it instead. hasNoFollowSupport is read once
// at module load, which is why the module is loaded inside isolateModules.
function loadWithoutNoFollow(): Loaded {
    let loaded!: Loaded;
    jest.isolateModules(() => {
        jest.doMock('fs', () => {
            const real = jest.requireActual<typeof fs>('fs');
            const { O_NOFOLLOW: _dropped, ...constants } = real.constants;
            return { ...real, constants };
        });
        loaded = {
            GCPKeyValueStorage: require('../src/GCPKeyValueStore').GCPKeyValueStorage,
            GCPKeyConfig: require('../src/GcpKeyConfig').GCPKeyConfig,
            GCPKSMClient: require('../src/GcpKmsClient').GCPKSMClient,
            GCPKeyValueStorageError: require('../src/error').GCPKeyValueStorageError,
        };
    });
    jest.dontMock('fs');
    return loaded;
}

describe('GCPKeyValueStorage where O_NOFOLLOW and process.getuid are absent (Windows)', () => {
    let tmpDir: string;
    let configPath: string;
    let attackerPath: string;
    let attackerBytes: Buffer;
    const realGetuid = process.getuid;
    let lib: Loaded;

    const makeStorage = (storagePath: string = configPath) => {
        const sessionConfig = new lib.GCPKSMClient();
        const storage = new lib.GCPKeyValueStorage(
            storagePath,
            new lib.GCPKeyConfig(KEY_RESOURCE_NAME),
            sessionConfig
        );
        const cryptoClient = sessionConfig.getCryptoClient();
        (cryptoClient.getCryptoKey as jest.Mock).mockResolvedValue([
            { purpose: 'ENCRYPT_DECRYPT', versionTemplate: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION' } },
        ]);
        (cryptoClient.encrypt as jest.Mock).mockImplementation(async (input: { plaintext: Buffer }) => [{
            ciphertext: input.plaintext,
            verifiedPlaintextCrc32c: true,
            ciphertextCrc32c: { value: calculate(input.plaintext) },
        }]);
        (cryptoClient.decrypt as jest.Mock).mockImplementation(async (input: { ciphertext: Buffer }) => [{
            plaintext: input.ciphertext,
            plaintextCrc32c: { value: calculate(input.ciphertext) },
        }]);
        (storage as any).initialized = true;
        return storage;
    };

    beforeEach(async () => {
        delete (process as any).getuid;
        lib = loadWithoutNoFollow();
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-kms-nonofollow-'));
        configPath = path.join(tmpDir, 'config.json');
        attackerPath = path.join(tmpDir, 'attacker-config.json');
        // A valid encrypted config, so that reading through the link succeeds and the attacker's
        // values are what the storage would adopt. Bytes that fail to decrypt would make the
        // tests fail for an unrelated reason.
        const seed = makeStorage(attackerPath);
        await seed.init();
        await seed.saveString('clientId', 'ATTACKER-CLIENT-ID');
        attackerBytes = fs.readFileSync(attackerPath);
        fs.symlinkSync(attackerPath, configPath);
    });

    afterEach(() => {
        (process as any).getuid = realGetuid;
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('decryptConfig(false) refuses a symlinked config path instead of reading through it', async () => {
        const rejection = await makeStorage().decryptConfig(false).then(() => null, (err) => err);

        expect(rejection).toBeInstanceOf(lib.GCPKeyValueStorageError);
        expect((rejection as Error).message).toMatch(/symbolic link/);
        expect(fs.readFileSync(attackerPath)).toEqual(attackerBytes);
    });

    it('decryptConfig(true) leaves the symlink in place and writes no plaintext over it', async () => {
        await makeStorage().decryptConfig(true).then(() => null, () => null);

        expect(fs.lstatSync(configPath).isSymbolicLink()).toBe(true);
        expect(fs.readFileSync(attackerPath)).toEqual(attackerBytes);
    });
});
