import { AWSSessionConfig } from '../src/AwsSessionConfig';

describe('AWSSessionConfig', () => {
    describe('constructor', () => {
        it('should create config with valid parameters', () => {
            // Given
            const awsAccessKeyId = 'AKIAIOSFODNN7EXAMPLE';
            const awsSecretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
            const regionName = 'us-east-1';

            // When
            const config = new AWSSessionConfig(awsAccessKeyId, awsSecretAccessKey, regionName);

            // Then
            expect(config.awsAccessKeyId).toBe(awsAccessKeyId);
            expect(config.awsSecretAccessKey).toBe(awsSecretAccessKey);
            expect(config.regionName).toBe(regionName);
        });

        it('should handle empty string values', () => {
            // When
            const config = new AWSSessionConfig('', '', '');

            // Then
            expect(config.awsAccessKeyId).toBe('');
            expect(config.awsSecretAccessKey).toBe('');
            expect(config.regionName).toBe('');
        });

        it('should store all provided values correctly', () => {
            // Given
            const configs = [
                ['AKIAIOSFODNN7EXAMPLE', 'secret1', 'us-east-1'],
                ['AKIATESTKEYID123456', 'very-long-secret-key-here', 'eu-west-1'],
                ['AKIA', 's', 'us-west-2']
            ];

            configs.forEach(([accessKey, secretKey, region]) => {
                // When
                const config = new AWSSessionConfig(accessKey, secretKey, region);

                // Then
                expect(config.awsAccessKeyId).toBe(accessKey);
                expect(config.awsSecretAccessKey).toBe(secretKey);
                expect(config.regionName).toBe(region);
            });
        });
    });

    describe('property assignment', () => {
        it('should allow modifying awsAccessKeyId after creation', () => {
            // Given
            const config = new AWSSessionConfig('AKIAORIGINAL', 'secret', 'us-east-1');
            const newAccessKeyId = 'AKIANEWKEYID';

            // When
            config.awsAccessKeyId = newAccessKeyId;

            // Then
            expect(config.awsAccessKeyId).toBe(newAccessKeyId);
            expect(config.awsSecretAccessKey).toBe('secret');
            expect(config.regionName).toBe('us-east-1');
        });

        it('should allow modifying awsSecretAccessKey after creation', () => {
            // Given
            const config = new AWSSessionConfig('AKIATEST', 'original-secret', 'us-east-1');
            const newSecretAccessKey = 'new-secret-key';

            // When
            config.awsSecretAccessKey = newSecretAccessKey;

            // Then
            expect(config.awsAccessKeyId).toBe('AKIATEST');
            expect(config.awsSecretAccessKey).toBe(newSecretAccessKey);
            expect(config.regionName).toBe('us-east-1');
        });

        it('should allow modifying regionName after creation', () => {
            // Given
            const config = new AWSSessionConfig('AKIATEST', 'secret', 'us-east-1');
            const newRegionName = 'eu-central-1';

            // When
            config.regionName = newRegionName;

            // Then
            expect(config.awsAccessKeyId).toBe('AKIATEST');
            expect(config.awsSecretAccessKey).toBe('secret');
            expect(config.regionName).toBe(newRegionName);
        });

        it('should allow setting properties to empty strings', () => {
            // Given
            const config = new AWSSessionConfig('AKIATEST', 'secret', 'us-east-1');

            // When
            config.awsAccessKeyId = '';
            config.awsSecretAccessKey = '';
            config.regionName = '';

            // Then
            expect(config.awsAccessKeyId).toBe('');
            expect(config.awsSecretAccessKey).toBe('');
            expect(config.regionName).toBe('');
        });
    });

    describe('AWS-specific formats', () => {
        it('should accept valid AWS access key ID formats', () => {
            // Given - AWS access keys start with AKIA, ASIA, etc.
            const accessKeyIds = [
                'AKIAIOSFODNN7EXAMPLE',           // Long-term credential
                'ASIATESTACCESSKEY123',            // Temporary credential (STS)
                'AKIA1234567890ABCDEF',            // Standard format
                'AKIAT1234567890ABCDE'             // Varied length
            ];

            accessKeyIds.forEach(accessKeyId => {
                // When
                const config = new AWSSessionConfig(accessKeyId, 'test-secret', 'us-east-1');

                // Then
                expect(config.awsAccessKeyId).toBe(accessKeyId);
            });
        });

        it('should accept valid AWS region name formats', () => {
            // Given - AWS region formats
            const regionNames = [
                'us-east-1',                // US East (N. Virginia)
                'us-west-2',                // US West (Oregon)
                'eu-central-1',             // Europe (Frankfurt)
                'ap-southeast-1',           // Asia Pacific (Singapore)
                'ca-central-1',             // Canada (Central)
                'sa-east-1',                // South America (São Paulo)
                'us-gov-west-1',            // AWS GovCloud (US-West)
                'cn-north-1',               // China (Beijing)
                'me-south-1',               // Middle East (Bahrain)
                'af-south-1'                // Africa (Cape Town)
            ];

            regionNames.forEach(regionName => {
                // When
                const config = new AWSSessionConfig('AKIATEST', 'test-secret', regionName);

                // Then
                expect(config.regionName).toBe(regionName);
            });
        });

        it('should accept various secret access key formats', () => {
            // Given - AWS secret access keys are 40 characters
            const secretAccessKeys = [
                'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                'abcdefghijklmnopqrstuvwxyz0123456789+/AB',
                'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T',
                '1234567890abcdefghijklmnopqrstuvwxyz+/=='
            ];

            secretAccessKeys.forEach(secretAccessKey => {
                // When
                const config = new AWSSessionConfig('AKIATEST', secretAccessKey, 'us-east-1');

                // Then
                expect(config.awsSecretAccessKey).toBe(secretAccessKey);
            });
        });
    });
});
