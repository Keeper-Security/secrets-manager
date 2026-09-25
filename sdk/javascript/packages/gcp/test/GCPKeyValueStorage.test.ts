// Mock GCP SDK modules BEFORE importing anything
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
jest.mock('fs', () => ({
    promises: {
        readFile: jest.fn(),
        writeFile: jest.fn(),
        mkdir: jest.fn(),
        access: jest.fn(),
        chmod: jest.fn(),
    },
    // Real, static flag values only, no I/O. secrets-manager-core reads fs.constants at
    // module load time (cache directory symlink protection), so a mock missing it entirely
    // fails every test in this file before any test body runs.
    constants: jest.requireActual('fs').constants,
}));

import { promises as fs } from 'fs';
import { resolve } from 'path';
import { GCPKeyValueStorage } from '../src/GCPKeyValueStore';
import { GCPKeyConfig } from '../src/GcpKeyConfig';
import { GCPKSMClient } from '../src/GcpKmsClient';

describe('GCPKeyValueStorage', () => {
    let mockSessionConfig: GCPKSMClient;

    beforeEach(() => {
        mockSessionConfig = new GCPKSMClient();
    });

    describe('constructor', () => {
        it('should create instance with valid parameters', () => {
            // Given
            const configFileLocation = './test-config.json';
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );

            // When/Then - Constructor should not throw
            expect(() => {
                new GCPKeyValueStorage(configFileLocation, gcpKeyConfig, mockSessionConfig);
            }).not.toThrow();
        });

        it('should create instance with null config file location', () => {
            // Given
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );

            // When/Then
            expect(() => {
                new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);
            }).not.toThrow();
        });

        it('should create instance with log level', () => {
            // Given
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );

            // When/Then
            expect(() => {
                new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig, 'info' as any);
            }).not.toThrow();
        });
    });

    describe('constructor with various key configs', () => {
        it('should accept resource name with version', () => {
            // Given
            const resourceName = 'projects/my-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1';
            const gcpKeyConfig = new GCPKeyConfig(resourceName);

            // When/Then
            expect(() => {
                new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);
            }).not.toThrow();
        });

        it('should accept config with empty version', () => {
            // Given - Using individual params to allow empty version
            const gcpKeyConfig = new GCPKeyConfig(undefined, 'my-key', 'my-ring', 'my-project', 'us-central1', '');

            // When/Then
            expect(() => {
                new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);
            }).not.toThrow();
        });

        it('should accept configs from different regions', () => {
            // Given
            const regions = ['us-central1', 'europe-west1', 'asia-east1'];

            regions.forEach(region => {
                const resourceName = `projects/test-project/locations/${region}/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1`;
                const gcpKeyConfig = new GCPKeyConfig(resourceName);

                // When/Then
                expect(() => {
                    new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);
                }).not.toThrow();
            });
        });
    });

    describe('interface implementation', () => {
        let storage: GCPKeyValueStorage;

        beforeEach(() => {
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );
            storage = new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);
        });

        it('should have getString method', () => {
            expect(storage.getString).toBeDefined();
            expect(typeof storage.getString).toBe('function');
        });

        it('should have saveString method', () => {
            expect(storage.saveString).toBeDefined();
            expect(typeof storage.saveString).toBe('function');
        });

        it('should have getBytes method', () => {
            expect(storage.getBytes).toBeDefined();
            expect(typeof storage.getBytes).toBe('function');
        });

        it('should have saveBytes method', () => {
            expect(storage.saveBytes).toBeDefined();
            expect(typeof storage.saveBytes).toBe('function');
        });

        it('should have getObject method', () => {
            expect(storage.getObject).toBeDefined();
            expect(typeof storage.getObject).toBe('function');
        });

        it('should have saveObject method', () => {
            expect(storage.saveObject).toBeDefined();
            expect(typeof storage.saveObject).toBe('function');
        });

        it('should have delete method', () => {
            expect(storage.delete).toBeDefined();
            expect(typeof storage.delete).toBe('function');
        });

        it('should have init method', () => {
            expect(storage.init).toBeDefined();
            expect(typeof storage.init).toBe('function');
        });

        it('should have decryptConfig method', () => {
            expect(storage.decryptConfig).toBeDefined();
            expect(typeof storage.decryptConfig).toBe('function');
        });

        it('should have changeKey method', () => {
            expect(storage.changeKey).toBeDefined();
            expect(typeof storage.changeKey).toBe('function');
        });
    });

    describe('configuration file paths', () => {
        it('should handle absolute config file paths', () => {
            // Given
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );
            const configFileLocation = '/absolute/path/to/config.json';

            // When/Then
            expect(() => {
                new GCPKeyValueStorage(configFileLocation, gcpKeyConfig, mockSessionConfig);
            }).not.toThrow();
        });

        it('should handle relative config file paths', () => {
            // Given
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );
            const configFileLocations = [
                './config.json',
                '../config.json',
                '../../nested/config.json'
            ];

            configFileLocations.forEach(configFileLocation => {
                // When/Then
                expect(() => {
                    new GCPKeyValueStorage(configFileLocation, gcpKeyConfig, mockSessionConfig);
                }).not.toThrow();
            });
        });
    });

    describe('key config variations', () => {
        it('should handle symmetric encryption keys', () => {
            // Given
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/symmetric-key/cryptoKeyVersions/1'
            );

            // When/Then
            expect(() => {
                new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);
            }).not.toThrow();
        });

        it('should handle asymmetric encryption keys', () => {
            // Given
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/asymmetric-key/cryptoKeyVersions/1'
            );

            // When/Then
            expect(() => {
                new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);
            }).not.toThrow();
        });

        it('should handle HSM keys', () => {
            // Given
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/hsm-key/cryptoKeyVersions/1'
            );

            // When/Then
            expect(() => {
                new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);
            }).not.toThrow();
        });
    });

    // KSM-867: getKeyDetails() silently swallows errors — init() should propagate
    describe('init() error propagation — KSM-867 regression', () => {
        it('init() should throw when getCryptoKey fails (bad credentials)', async () => {
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );
            const storage = new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);

            // Make getCryptoKey reject — simulates bad credentials or non-existent key
            const mockClient = mockSessionConfig.getCryptoClient();
            (mockClient.getCryptoKey as jest.Mock).mockRejectedValue(
                new Error('PERMISSION_DENIED: The caller does not have permission')
            );

            // BUG: init() silently swallows this error instead of propagating
            await expect(storage.init()).rejects.toThrow('PERMISSION_DENIED');
        });

        it('init() should throw when getCryptoKey fails (non-existent key)', async () => {
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/nonexistent/cryptoKeyVersions/1'
            );
            const storage = new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);

            const mockClient = mockSessionConfig.getCryptoClient();
            (mockClient.getCryptoKey as jest.Mock).mockRejectedValue(
                new Error('NOT_FOUND: CryptoKey not found')
            );

            await expect(storage.init()).rejects.toThrow('NOT_FOUND');
        });
    });

    // KSM-837: Regression tests for contains() — incorrect `in` operator usage
    describe('contains() — KSM-837 regression', () => {
        let storage: GCPKeyValueStorage;
        let mockConfig: Record<string, string>;

        beforeEach(() => {
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );
            storage = new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);

            mockConfig = { clientId: 'abc', appKey: 'xyz' };

            jest.spyOn(storage, 'readStorage').mockResolvedValue(mockConfig);
            jest.spyOn(storage, 'saveStorage').mockResolvedValue(undefined);
        });

        afterEach(() => {
            jest.restoreAllMocks();
        });

        it('contains() should return true for an existing key', async () => {
            const result = await storage.contains('clientId');
            expect(result).toBe(true);
        });

        it('contains() should return false for a missing key', async () => {
            const result = await storage.contains('nonexistent');
            expect(result).toBe(false);
        });
    });

    // KSM-849: Regression tests — getBytes() must return empty Uint8Array for zero-length values
    describe('getBytes() zero-length Uint8Array — KSM-849 regression', () => {
        let storage: GCPKeyValueStorage;

        beforeEach(() => {
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );
            storage = new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);
        });

        afterEach(() => {
            jest.restoreAllMocks();
        });

        it('getBytes() should return a defined empty Uint8Array for a key storing zero-length bytes', async () => {
            // Given: empty Uint8Array was previously saved (stored as empty base64 string "")
            jest.spyOn(storage, 'readStorage').mockResolvedValue({ emptyKey: '' });

            // When
            const result = await storage.getBytes('emptyKey');

            // Then: must return Uint8Array(0), not undefined
            expect(result).toBeDefined();
            expect(result).toBeInstanceOf(Uint8Array);
            expect(result!.length).toBe(0);
        });

        it('getBytes() should still return undefined for a key that was never saved', async () => {
            // Given: key is absent from storage
            jest.spyOn(storage, 'readStorage').mockResolvedValue({});

            // When
            const result = await storage.getBytes('missingKey');

            // Then
            expect(result).toBeUndefined();
        });

        it('contains() and getBytes() must be consistent: if contains returns true, getBytes must return defined', async () => {
            // Given: empty Uint8Array stored
            jest.spyOn(storage, 'readStorage').mockResolvedValue({ emptyKey: '' });

            // When
            const exists = await storage.contains('emptyKey');
            const value = await storage.getBytes('emptyKey');

            // Then
            expect(exists).toBe(true);
            expect(value).toBeDefined();
        });
    });

    // KSM-840: Regression tests for delete() — truthy check skips falsy values
    describe('delete() — KSM-840 regression', () => {
        let storage: GCPKeyValueStorage;

        beforeEach(() => {
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );
            storage = new GCPKeyValueStorage(null, gcpKeyConfig, mockSessionConfig);
        });

        afterEach(() => {
            jest.restoreAllMocks();
        });

        it('delete() should remove a key whose value is an empty string', async () => {
            const mockConfig: Record<string, string> = { emptyKey: '' };
            jest.spyOn(storage, 'readStorage').mockResolvedValue(mockConfig);
            jest.spyOn(storage, 'saveStorage').mockResolvedValue(undefined);

            await storage.delete('emptyKey');

            expect(mockConfig).not.toHaveProperty('emptyKey');
        });

        it('delete() should remove a key whose value is falsy (0)', async () => {
            const mockConfig: Record<string, any> = { zeroKey: 0 };
            jest.spyOn(storage, 'readStorage').mockResolvedValue(mockConfig);
            jest.spyOn(storage, 'saveStorage').mockResolvedValue(undefined);

            await storage.delete('zeroKey');

            expect(mockConfig).not.toHaveProperty('zeroKey');
        });

        it('delete() should log "not found" for a truly missing key', async () => {
            const mockConfig: Record<string, string> = {};
            jest.spyOn(storage, 'readStorage').mockResolvedValue(mockConfig);
            jest.spyOn(storage, 'saveStorage').mockResolvedValue(undefined);

            // Should not throw; saveStorage still called
            await expect(storage.delete('missing')).resolves.toBeUndefined();
        });
    });

    describe('createConfigFileIfMissing() fs.access error handling', () => {
        let storage: GCPKeyValueStorage;

        beforeEach(() => {
            jest.clearAllMocks();
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );
            storage = new GCPKeyValueStorage('./test-config.json', gcpKeyConfig, mockSessionConfig);
            const cryptoClient = mockSessionConfig.getCryptoClient();
            (cryptoClient.getCryptoKey as jest.Mock).mockResolvedValue([
                { purpose: 'ENCRYPT_DECRYPT', versionTemplate: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION' } },
            ]);
        });

        // Table-driven so narrowing the ENOENT check later (e.g. to `!== "ENOENT" && !== "EPERM"`)
        // reopens the hole for one code without this test noticing. Goes through the public
        // init() entry point (getKeyDetails() -> loadConfig() -> createConfigFileIfMissing()),
        // not the private method directly, so a regression that swallows the rejection instead
        // of throwing it - the actual security property KSM-1370 exists to guarantee - fails
        // this test. A `.catch(() => undefined)` assertion on write-not-called alone can't tell
        // the difference between "rejected" and "silently returned".
        it.each(['EACCES', 'EPERM', 'ESTALE', 'EIO', 'EBUSY'])(
            'init() rejects and writes nothing when fs.access fails with %s',
            async (code) => {
                const accessError = Object.assign(new Error(`${code}: access failure`), { code });
                (fs.access as jest.Mock).mockRejectedValue(accessError);

                // fs.writeFile isn't in the write path anymore (writeFileAtomicSync is); asserting
                // against it would pass unconditionally regardless of what init() actually does.
                // mockImplementation stops a regression that does reach this call from performing
                // a real filesystem write in this test's temp-free setup.
                const atomicWrite = require('../src/atomicWrite');
                const spy = jest.spyOn(atomicWrite, 'writeFileAtomicSync').mockImplementation(() => undefined);

                await expect(storage.init()).rejects.toMatchObject({ code });
                expect(spy).not.toHaveBeenCalled();
                spy.mockRestore();
            }
        );

        it('saveString() also rejects and writes nothing when fs.access fails with EACCES', async () => {
            const accessError = Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' });
            (fs.access as jest.Mock).mockRejectedValue(accessError);

            const atomicWrite = require('../src/atomicWrite');
            const spy = jest.spyOn(atomicWrite, 'writeFileAtomicSync').mockImplementation(() => undefined);

            await expect(storage.saveString('clientId', 'x')).rejects.toMatchObject({ code: 'EACCES' });
            expect(spy).not.toHaveBeenCalled();
            spy.mockRestore();
        });

        // The ENOENT-still-creates case and the config-file-permission assertions that used to
        // live here both moved to GCPKeyValueStorage.atomicWrite.test.ts: on ENOENT, this method
        // falls through to writeFileAtomicSync's real, unmocked sync fs calls (openSync/writeSync/
        // renameSync), and this file's blanket jest.mock('fs', ...) only stubs `fs.promises` - so
        // `fs.openSync` etc. don't exist under it, and asserting against the old
        // fs.promises.writeFile/chmod mocks would just prove those mocks are never called.
    });

    describe('configFileLocation resolution (KSM-1457 regression)', () => {
        const DEFAULT_CONFIG_FILE = 'client-config.json';
        let savedConfigFileEnv: string | undefined;

        beforeEach(() => {
            savedConfigFileEnv = process.env.KSM_CONFIG_FILE;
            delete process.env.KSM_CONFIG_FILE;
            // mockReset, not mockClear: an earlier describe leaves a mockRejectedValue on this
            // shared mock, and the call history has to be empty for the path assertions below.
            (fs.access as jest.Mock).mockReset();
            (fs.access as jest.Mock).mockResolvedValue(undefined);
        });

        afterEach(() => {
            if (savedConfigFileEnv === undefined) {
                delete process.env.KSM_CONFIG_FILE;
            } else {
                process.env.KSM_CONFIG_FILE = savedConfigFileEnv;
            }
        });

        const makeStorage = (location: string | null): GCPKeyValueStorage => {
            const gcpKeyConfig = new GCPKeyConfig(
                'projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1'
            );
            return new GCPKeyValueStorage(location, gcpKeyConfig, mockSessionConfig);
        };

        const configFileLocationOf = (storage: GCPKeyValueStorage): string =>
            (storage as any).configFileLocation;

        // Table-driven: '' is the case the ticket reports, the whitespace-only values are the
        // same accident from an env file or ConfigMap that pads the value instead of emptying it.
        it.each(['', ' ', '   ', '\t', '\n'])(
            'uses the default config file when the explicit location is blank (%j)',
            (location) => {
                expect(configFileLocationOf(makeStorage(location))).toBe(DEFAULT_CONFIG_FILE);
            }
        );

        it.each(['', ' ', '   ', '\t', '\n'])(
            'uses the default config file when KSM_CONFIG_FILE is blank (%j)',
            (envValue) => {
                process.env.KSM_CONFIG_FILE = envValue;

                expect(configFileLocationOf(makeStorage(null))).toBe(DEFAULT_CONFIG_FILE);
            }
        );

        it('falls back to KSM_CONFIG_FILE when only the explicit location is blank', () => {
            process.env.KSM_CONFIG_FILE = '/etc/keeper/from-env.json';

            expect(configFileLocationOf(makeStorage(''))).toBe('/etc/keeper/from-env.json');
        });

        it('still uses a non-empty KSM_CONFIG_FILE when no location is passed', () => {
            process.env.KSM_CONFIG_FILE = '/etc/keeper/from-env.json';

            expect(configFileLocationOf(makeStorage(null))).toBe('/etc/keeper/from-env.json');
        });

        it('still prefers a non-empty explicit location over KSM_CONFIG_FILE', () => {
            process.env.KSM_CONFIG_FILE = '/etc/keeper/from-env.json';

            expect(configFileLocationOf(makeStorage('./explicit-config.json'))).toBe('./explicit-config.json');
        });

        it('still uses the default config file when neither source is set', () => {
            expect(configFileLocationOf(makeStorage(null))).toBe(DEFAULT_CONFIG_FILE);
        });

        // The field assertions above pin the value; this pins the consequence the ticket is
        // actually about. resolve('') is the current working directory, and fs.access on a
        // directory succeeds, so a blank value made createConfigFileIfMissing() report the
        // working directory itself as an existing config file.
        it('does not check the current working directory as the config file when KSM_CONFIG_FILE is blank', async () => {
            process.env.KSM_CONFIG_FILE = '';
            const storage = makeStorage(null);

            await (storage as any).createConfigFileIfMissing();

            expect(fs.access).toHaveBeenCalledWith(resolve(DEFAULT_CONFIG_FILE));
            expect(fs.access).not.toHaveBeenCalledWith(process.cwd());
        });
    });
});
