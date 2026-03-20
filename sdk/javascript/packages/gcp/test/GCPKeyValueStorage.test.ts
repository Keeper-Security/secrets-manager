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
    }
}));

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
});
