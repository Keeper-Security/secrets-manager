import { AWSKeyValueStorage } from '../src/AwsKeyValueStore';
import { AWSSessionConfig } from '../src/AwsSessionConfig';

// Mock AWS SDK modules
jest.mock('@aws-sdk/client-kms');
jest.mock('../src/AwsKmsClient', () => ({
    AwsKmsClient: jest.fn().mockImplementation(() => ({
        getCryptoClient: jest.fn().mockReturnValue({
            send: jest.fn(),
        }),
    })),
}));
jest.mock('fs', () => ({
    promises: {
        readFile: jest.fn(),
        writeFile: jest.fn(),
        mkdir: jest.fn(),
        access: jest.fn(),
    }
}));

// Mock Logger
jest.mock('../src/Logger', () => ({
    getLogger: jest.fn(() => ({
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
    }))
}));

describe('AWSKeyValueStorage', () => {
    describe('constructor', () => {
        it('should create instance with valid parameters', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const configFileLocation = './test-config.json';
            const awsSessionConfig = new AWSSessionConfig('AKIATEST', 'secret-key', 'us-east-1');

            // When/Then - Constructor should not throw
            expect(() => {
                new AWSKeyValueStorage(keyId, configFileLocation, awsSessionConfig, null as any);
            }).not.toThrow();
        });

        it('should create instance with null config file location', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const awsSessionConfig = new AWSSessionConfig('AKIATEST', 'secret-key', 'us-east-1');

            // When/Then
            expect(() => {
                new AWSKeyValueStorage(keyId, null, awsSessionConfig, null as any);
            }).not.toThrow();
        });

        it('should create instance with null session config', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const configFileLocation = './test-config.json';

            // When/Then
            expect(() => {
                new AWSKeyValueStorage(keyId, configFileLocation, null, null as any);
            }).not.toThrow();
        });

        it('should create instance with all null optional parameters', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

            // When/Then
            expect(() => {
                new AWSKeyValueStorage(keyId, null, null, null as any);
            }).not.toThrow();
        });
    });

    describe('constructor with various key ID formats', () => {
        it('should accept full ARN with key ID', () => {
            // Given - Full ARN format
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

            // When/Then
            expect(() => {
                new AWSKeyValueStorage(keyId, null, null, null as any);
            }).not.toThrow();
        });

        it('should accept ARN with alias', () => {
            // Given - Alias ARN format
            const keyId = 'arn:aws:kms:us-east-1:123456789012:alias/my-key-alias';

            // When/Then
            expect(() => {
                new AWSKeyValueStorage(keyId, null, null, null as any);
            }).not.toThrow();
        });

        it('should accept key ID only (without full ARN)', () => {
            // Given - Just the key ID
            const keyId = '12345678-1234-1234-1234-123456789012';

            // When/Then
            expect(() => {
                new AWSKeyValueStorage(keyId, null, null, null as any);
            }).not.toThrow();
        });

        it('should accept ARNs from different regions', () => {
            // Given
            const regionKeyIds = [
                'arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012',
                'arn:aws:kms:eu-central-1:123456789012:key/12345678-1234-1234-1234-123456789012',
                'arn:aws:kms:ap-southeast-1:123456789012:key/12345678-1234-1234-1234-123456789012'
            ];

            regionKeyIds.forEach(keyId => {
                // When/Then
                expect(() => {
                    new AWSKeyValueStorage(keyId, null, null, null as any);
                }).not.toThrow();
            });
        });

        it('should accept ARNs with different AWS partitions', () => {
            // Given
            const partitionKeyIds = [
                'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',         // Standard AWS
                'arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/12345678-1234-1234-1234-123456789012', // AWS GovCloud
                'arn:aws-cn:kms:cn-north-1:123456789012:key/12345678-1234-1234-1234-123456789012'     // AWS China
            ];

            partitionKeyIds.forEach(keyId => {
                // When/Then
                expect(() => {
                    new AWSKeyValueStorage(keyId, null, null, null as any);
                }).not.toThrow();
            });
        });
    });

    describe('interface implementation', () => {
        let storage: AWSKeyValueStorage;

        beforeEach(() => {
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const awsSessionConfig = new AWSSessionConfig('AKIATEST', 'secret-key', 'us-east-1');
            storage = new AWSKeyValueStorage(keyId, null, awsSessionConfig, null as any);
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
    });

    describe('configuration file paths', () => {
        it('should handle absolute config file paths', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const configFileLocation = '/absolute/path/to/config.json';

            // When/Then
            expect(() => {
                new AWSKeyValueStorage(keyId, configFileLocation, null, null as any);
            }).not.toThrow();
        });

        it('should handle relative config file paths', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const configFileLocations = [
                './config.json',
                '../config.json',
                '../../nested/config.json'
            ];

            configFileLocations.forEach(configFileLocation => {
                // When/Then
                expect(() => {
                    new AWSKeyValueStorage(keyId, configFileLocation, null, null as any);
                }).not.toThrow();
            });
        });
    });

    describe('session config variations', () => {
        it('should handle session config with empty strings', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const awsSessionConfig = new AWSSessionConfig('', '', '');

            // When/Then
            expect(() => {
                new AWSKeyValueStorage(keyId, null, awsSessionConfig, null as any);
            }).not.toThrow();
        });

        it('should handle session config with partial values', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

            // Test with only access key ID
            const config1 = new AWSSessionConfig('AKIATEST', '', '');
            expect(() => {
                new AWSKeyValueStorage(keyId, null, config1, null as any);
            }).not.toThrow();

            // Test with only secret access key
            const config2 = new AWSSessionConfig('', 'secret-only', '');
            expect(() => {
                new AWSKeyValueStorage(keyId, null, config2, null as any);
            }).not.toThrow();

            // Test with only region
            const config3 = new AWSSessionConfig('', '', 'us-east-1');
            expect(() => {
                new AWSKeyValueStorage(keyId, null, config3, null as any);
            }).not.toThrow();
        });

        it('should handle session config with different regions', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const regions = [
                'us-east-1',
                'us-west-2',
                'eu-central-1',
                'ap-southeast-1',
                'us-gov-west-1',
                'cn-north-1'
            ];

            regions.forEach(region => {
                // When
                const awsSessionConfig = new AWSSessionConfig('AKIATEST', 'secret-key', region);

                // Then
                expect(() => {
                    new AWSKeyValueStorage(keyId, null, awsSessionConfig, null as any);
                }).not.toThrow();
            });
        });
    });

    describe('default config file location', () => {
        it('should use default config file when none provided', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

            // When
            const storage = new AWSKeyValueStorage(keyId, null, null, null as any);

            // Then
            expect(storage.configFileLocation).toBe('client-config.json');
        });

        it('should use provided config file location over default', () => {
            // Given
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const customLocation = './custom-config.json';

            // When
            const storage = new AWSKeyValueStorage(keyId, customLocation, null, null as any);

            // Then
            expect(storage.configFileLocation).toBe(customLocation);
        });
    });

    // KSM-851: Regression tests — getBytes() must return empty Uint8Array for zero-length values
    describe('getBytes() zero-length Uint8Array — KSM-851 regression', () => {
        let storage: AWSKeyValueStorage;

        beforeEach(() => {
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const awsSessionConfig = new AWSSessionConfig('AKIATEST', 'secret-key', 'us-east-1');
            storage = new AWSKeyValueStorage(keyId, null, awsSessionConfig, null as any);
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

    // KSM-839: Regression tests for delete() — truthy check skips falsy values
    describe('delete() — KSM-839 regression', () => {
        let storage: AWSKeyValueStorage;

        beforeEach(() => {
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const awsSessionConfig = new AWSSessionConfig('AKIATEST', 'secret-key', 'us-east-1');
            storage = new AWSKeyValueStorage(keyId, null, awsSessionConfig, null as any);
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

    // KSM-836: Regression tests for contains() — incorrect `in` operator usage
    describe('contains() — KSM-836 regression', () => {
        let storage: AWSKeyValueStorage;
        let mockConfig: Record<string, string>;

        beforeEach(() => {
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const awsSessionConfig = new AWSSessionConfig('AKIATEST', 'secret-key', 'us-east-1');
            storage = new AWSKeyValueStorage(keyId, null, awsSessionConfig, null as any);

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
});
