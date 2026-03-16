// Mock OCI SDK modules BEFORE importing anything
jest.mock('oci-common', () => ({
    ConfigFileAuthenticationDetailsProvider: jest.fn().mockImplementation(() => ({})),
}));
jest.mock('oci-keymanagement', () => ({
    KmsCryptoClient: jest.fn().mockImplementation(() => ({
        encrypt: jest.fn(),
        decrypt: jest.fn(),
    })),
    KmsManagementClient: jest.fn().mockImplementation(() => ({
        getKey: jest.fn(),
    })),
}));
jest.mock('../src/OciKmsClient', () => ({
    OciKmsClient: jest.fn().mockImplementation(() => ({
        getCryptoClient: jest.fn().mockReturnValue({
            encrypt: jest.fn(),
            decrypt: jest.fn(),
        }),
        getManagementClient: jest.fn().mockReturnValue({
            getKey: jest.fn(),
        }),
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
    },
    existsSync: jest.fn().mockReturnValue(false),
    readFileSync: jest.fn().mockReturnValue(''),
}));

import { OciKeyValueStorage } from '../src/OracleKeyValueStore';
import { OCISessionConfig } from '../src/OciSessionConfig';

describe('OciKeyValueStorage', () => {
    describe('constructor', () => {
        it('should create instance with valid parameters', () => {
            // Given
            const keyId = 'ocid1.key.oc1.phx.example123';
            const keyVersion = 'version-1';
            const configFileLocation = './test-config.json';
            const ociSessionConfig = new OCISessionConfig(
                '~/.oci/config',
                'DEFAULT',
                'https://crypto.kms.us-phoenix-1.oraclecloud.com',
                'https://management.kms.us-phoenix-1.oraclecloud.com'
            );

            // When/Then - Constructor should not throw
            expect(() => {
                new OciKeyValueStorage(keyId, keyVersion, configFileLocation, ociSessionConfig, null);
            }).not.toThrow();
        });

        it('should create instance with null config file location', () => {
            // Given
            const keyId = 'ocid1.key.oc1.phx.example123';
            const ociSessionConfig = new OCISessionConfig(
                '~/.oci/config',
                'DEFAULT',
                'https://crypto.kms.us-phoenix-1.oraclecloud.com',
                'https://management.kms.us-phoenix-1.oraclecloud.com'
            );

            // When/Then
            expect(() => {
                new OciKeyValueStorage(keyId, null, null, ociSessionConfig, null);
            }).not.toThrow();
        });

        it('should create instance with null key version', () => {
            // Given
            const keyId = 'ocid1.key.oc1.phx.example123';
            const configFileLocation = './test-config.json';
            const ociSessionConfig = new OCISessionConfig(
                '~/.oci/config',
                'DEFAULT',
                'https://crypto.kms.us-phoenix-1.oraclecloud.com',
                'https://management.kms.us-phoenix-1.oraclecloud.com'
            );

            // When/Then
            expect(() => {
                new OciKeyValueStorage(keyId, null, configFileLocation, ociSessionConfig, null);
            }).not.toThrow();
        });

        it('should create instance with all null optional parameters', () => {
            // Given
            const keyId = 'ocid1.key.oc1.phx.example123';
            const ociSessionConfig = new OCISessionConfig(
                '~/.oci/config',
                'DEFAULT',
                'https://crypto.kms.us-phoenix-1.oraclecloud.com',
                'https://management.kms.us-phoenix-1.oraclecloud.com'
            );

            // When/Then
            expect(() => {
                new OciKeyValueStorage(keyId, null, null, ociSessionConfig, null);
            }).not.toThrow();
        });
    });

    describe('constructor with various key ID formats', () => {
        const ociSessionConfig = new OCISessionConfig(
            '~/.oci/config',
            'DEFAULT',
            'https://crypto.kms.us-phoenix-1.oraclecloud.com',
            'https://management.kms.us-phoenix-1.oraclecloud.com'
        );

        it('should accept key ID with version', () => {
            // Given - OCI key OCID with version
            const keyId = 'ocid1.key.oc1.phx.amaaaaaa4uieqyaabbbbccccddddeeeeffffffff';

            // When/Then
            expect(() => {
                new OciKeyValueStorage(keyId, 'version-1', null, ociSessionConfig, null);
            }).not.toThrow();
        });

        it('should accept key ID without version', () => {
            // Given - OCI key OCID without version
            const keyId = 'ocid1.key.oc1.phx.amaaaaaa4uieqyaa';

            // When/Then
            expect(() => {
                new OciKeyValueStorage(keyId, null, null, ociSessionConfig, null);
            }).not.toThrow();
        });

        it('should accept key IDs from different regions', () => {
            // Given
            const regions = ['phx', 'iad', 'fra', 'lhr', 'nrt'];

            regions.forEach(region => {
                const keyId = `ocid1.key.oc1.${region}.example123`;

                // When/Then
                expect(() => {
                    new OciKeyValueStorage(keyId, null, null, ociSessionConfig, null);
                }).not.toThrow();
            });
        });
    });

    describe('interface implementation', () => {
        let storage: OciKeyValueStorage;

        beforeEach(() => {
            const keyId = 'ocid1.key.oc1.phx.example123';
            const ociSessionConfig = new OCISessionConfig(
                '~/.oci/config',
                'DEFAULT',
                'https://crypto.kms.us-phoenix-1.oraclecloud.com',
                'https://management.kms.us-phoenix-1.oraclecloud.com'
            );
            storage = new OciKeyValueStorage(keyId, null, null, ociSessionConfig, null);
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

        it('should have delete method', () => {
            expect(storage.delete).toBeDefined();
            expect(typeof storage.delete).toBe('function');
        });
    });

    describe('configuration file paths', () => {
        const ociSessionConfig = new OCISessionConfig(
            '~/.oci/config',
            'DEFAULT',
            'https://crypto.kms.us-phoenix-1.oraclecloud.com',
            'https://management.kms.us-phoenix-1.oraclecloud.com'
        );

        it('should handle absolute config file paths', () => {
            // Given
            const keyId = 'ocid1.key.oc1.phx.example123';
            const configFileLocation = '/absolute/path/to/config.json';

            // When/Then
            expect(() => {
                new OciKeyValueStorage(keyId, null, configFileLocation, ociSessionConfig, null);
            }).not.toThrow();
        });

        it('should handle relative config file paths', () => {
            // Given
            const keyId = 'ocid1.key.oc1.phx.example123';
            const configFileLocations = [
                './config.json',
                '../config.json',
                '../../nested/config.json'
            ];

            configFileLocations.forEach(configFileLocation => {
                // When/Then
                expect(() => {
                    new OciKeyValueStorage(keyId, null, configFileLocation, ociSessionConfig, null);
                }).not.toThrow();
            });
        });
    });

    // KSM-838: Regression tests for contains() — incorrect `in` operator usage
    describe('contains() — KSM-838 regression', () => {
        let storage: OciKeyValueStorage;
        let mockConfig: Record<string, string>;

        beforeEach(() => {
            const keyId = 'ocid1.key.oc1.phx.example123';
            const ociSessionConfig = new OCISessionConfig(
                '~/.oci/config',
                'DEFAULT',
                'https://crypto.kms.us-phoenix-1.oraclecloud.com',
                'https://management.kms.us-phoenix-1.oraclecloud.com'
            );
            storage = new OciKeyValueStorage(keyId, null, null, ociSessionConfig, null);

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

    // KSM-841: Regression tests for delete() — truthy check skips falsy values
    describe('delete() — KSM-841 regression', () => {
        let storage: OciKeyValueStorage;

        beforeEach(() => {
            const keyId = 'ocid1.key.oc1.phx.example123';
            const ociSessionConfig = new OCISessionConfig(
                '~/.oci/config',
                'DEFAULT',
                'https://crypto.kms.us-phoenix-1.oraclecloud.com',
                'https://management.kms.us-phoenix-1.oraclecloud.com'
            );
            storage = new OciKeyValueStorage(keyId, null, null, ociSessionConfig, null);
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
