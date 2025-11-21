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
});
