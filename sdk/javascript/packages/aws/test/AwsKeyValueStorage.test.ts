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
});
