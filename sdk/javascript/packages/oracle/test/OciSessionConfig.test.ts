import { OCISessionConfig } from '../src/OciSessionConfig';

// Mock OCI SDK
jest.mock('oci-common');

describe('OCISessionConfig', () => {
    describe('constructor', () => {
        it('should create config with valid parameters', () => {
            // Given
            const ociConfigFileLocation = '~/.oci/config';
            const profile = 'DEFAULT';
            const cryptoEndpoint = 'https://crypto.kms.us-phoenix-1.oraclecloud.com';
            const managementEndpoint = 'https://management.kms.us-phoenix-1.oraclecloud.com';

            // When
            const config = new OCISessionConfig(
                ociConfigFileLocation,
                profile,
                cryptoEndpoint,
                managementEndpoint
            );

            // Then
            expect(config.ociConfigFileLocation).toBe(ociConfigFileLocation);
            expect(config.profile).toBe(profile);
            expect(config.ksmCryptoEndpoint).toBe(cryptoEndpoint);
            expect(config.ksmManagementEndpoint).toBe(managementEndpoint);
        });

        it('should default profile to DEFAULT when null is provided', () => {
            // Given
            const ociConfigFileLocation = '~/.oci/config';
            const cryptoEndpoint = 'https://crypto.kms.us-phoenix-1.oraclecloud.com';
            const managementEndpoint = 'https://management.kms.us-phoenix-1.oraclecloud.com';

            // When
            const config = new OCISessionConfig(
                ociConfigFileLocation,
                null,
                cryptoEndpoint,
                managementEndpoint
            );

            // Then
            expect(config.profile).toBe('DEFAULT');
        });

        it('should handle empty string values', () => {
            // When
            const config = new OCISessionConfig('', '', '', '');

            // Then
            expect(config.ociConfigFileLocation).toBe('');
            expect(config.profile).toBe('DEFAULT'); // Empty string is falsy, so defaults to DEFAULT
            expect(config.ksmCryptoEndpoint).toBe('');
            expect(config.ksmManagementEndpoint).toBe('');
        });

        it('should store all provided values correctly', () => {
            // Given
            const configs = [
                ['~/.oci/config', 'PROD', 'https://crypto-prod.com', 'https://mgmt-prod.com'],
                ['/home/user/.oci/config', 'DEV', 'https://crypto-dev.com', 'https://mgmt-dev.com'],
                ['C:\\Users\\user\\.oci\\config', 'TEST', 'https://crypto-test.com', 'https://mgmt-test.com']
            ];

            configs.forEach(([location, profile, crypto, mgmt]) => {
                // When
                const config = new OCISessionConfig(location, profile, crypto, mgmt);

                // Then
                expect(config.ociConfigFileLocation).toBe(location);
                expect(config.profile).toBe(profile);
                expect(config.ksmCryptoEndpoint).toBe(crypto);
                expect(config.ksmManagementEndpoint).toBe(mgmt);
            });
        });
    });

    describe('getProvider', () => {
        it('should return ConfigFileAuthenticationDetailsProvider', () => {
            // Given
            const config = new OCISessionConfig(
                '~/.oci/config',
                'DEFAULT',
                'https://crypto.example.com',
                'https://mgmt.example.com'
            );

            // When
            const provider = config.getProvider();

            // Then
            expect(provider).toBeDefined();
        });
    });

    describe('getKmsCryptoEndpoint', () => {
        it('should return the crypto endpoint', () => {
            // Given
            const cryptoEndpoint = 'https://crypto.kms.us-phoenix-1.oraclecloud.com';
            const config = new OCISessionConfig(
                '~/.oci/config',
                'DEFAULT',
                cryptoEndpoint,
                'https://mgmt.example.com'
            );

            // When
            const result = config.getKmsCryptoEndpoint();

            // Then
            expect(result).toBe(cryptoEndpoint);
        });
    });

    describe('getKmsManagementEndpoint', () => {
        it('should return the management endpoint', () => {
            // Given
            const managementEndpoint = 'https://management.kms.us-phoenix-1.oraclecloud.com';
            const config = new OCISessionConfig(
                '~/.oci/config',
                'DEFAULT',
                'https://crypto.example.com',
                managementEndpoint
            );

            // When
            const result = config.getKmsManagementEndpoint();

            // Then
            expect(result).toBe(managementEndpoint);
        });
    });

    describe('OCI-specific formats', () => {
        it('should accept valid OCI config file paths', () => {
            // Given - various OCI config file locations
            const configPaths = [
                '~/.oci/config',
                '/home/oracle/.oci/config',
                'C:\\Users\\oracle\\.oci\\config',
                './oci-config/config'
            ];

            configPaths.forEach(configPath => {
                // When
                const config = new OCISessionConfig(
                    configPath,
                    'DEFAULT',
                    'https://crypto.example.com',
                    'https://mgmt.example.com'
                );

                // Then
                expect(config.ociConfigFileLocation).toBe(configPath);
            });
        });

        it('should accept valid OCI profile names', () => {
            // Given - various OCI profile names
            const profiles = [
                'DEFAULT',
                'PROD',
                'DEV',
                'TEST',
                'USER1',
                'prod-profile',
                'dev_profile'
            ];

            profiles.forEach(profile => {
                // When
                const config = new OCISessionConfig(
                    '~/.oci/config',
                    profile,
                    'https://crypto.example.com',
                    'https://mgmt.example.com'
                );

                // Then
                expect(config.profile).toBe(profile);
            });
        });

        it('should accept valid OCI KMS endpoint formats', () => {
            // Given - various OCI KMS endpoint formats
            const regions = [
                'us-phoenix-1',
                'us-ashburn-1',
                'eu-frankfurt-1',
                'ap-tokyo-1',
                'uk-london-1'
            ];

            regions.forEach(region => {
                const cryptoEndpoint = `https://crypto.kms.${region}.oraclecloud.com`;
                const managementEndpoint = `https://management.kms.${region}.oraclecloud.com`;

                // When
                const config = new OCISessionConfig(
                    '~/.oci/config',
                    'DEFAULT',
                    cryptoEndpoint,
                    managementEndpoint
                );

                // Then
                expect(config.ksmCryptoEndpoint).toBe(cryptoEndpoint);
                expect(config.ksmManagementEndpoint).toBe(managementEndpoint);
            });
        });
    });
});
