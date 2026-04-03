// Mock Logger BEFORE importing anything
jest.mock('../src/Logger', () => ({
    getLogger: jest.fn().mockReturnValue({
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
    }),
}));

import { GCPKeyConfig } from '../src/GcpKeyConfig';

describe('GCPKeyConfig', () => {
    describe('constructor with resource name', () => {
        it('should create config from full resource name with version', () => {
            // Given
            const resourceName = 'projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1';

            // When
            const config = new GCPKeyConfig(resourceName);

            // Then
            expect(config.project).toBe('my-project');
            expect(config.location).toBe('us-central1');
            expect(config.keyRing).toBe('my-keyring');
            expect(config.keyName).toBe('my-key');
            expect(config.keyVersion).toBe('1');
        });

        it('should create config from resource name with empty version', () => {
            // Given - Using individual params to allow empty version
            const config = new GCPKeyConfig(undefined, 'my-key', 'my-keyring', 'my-project', 'us-central1', '');

            // Then
            expect(config.project).toBe('my-project');
            expect(config.location).toBe('us-central1');
            expect(config.keyRing).toBe('my-keyring');
            expect(config.keyName).toBe('my-key');
            expect(config.keyVersion).toBe('');
        });

        it('should create config with different GCP regions', () => {
            // Given
            const regions = [
                'us-central1',
                'us-east1',
                'europe-west1',
                'asia-east1',
                'australia-southeast1'
            ];

            regions.forEach(region => {
                const resourceName = `projects/test-project/locations/${region}/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1`;

                // When
                const config = new GCPKeyConfig(resourceName);

                // Then
                expect(config.location).toBe(region);
            });
        });
    });

    describe('constructor with individual parameters', () => {
        it('should create config with individual parameters', () => {
            // Given
            const keyName = 'my-key';
            const keyRing = 'my-keyring';
            const project = 'my-project';
            const location = 'us-central1';
            const keyVersion = '1';

            // When
            const config = new GCPKeyConfig(undefined, keyName, keyRing, project, location, keyVersion);

            // Then
            expect(config.keyName).toBe(keyName);
            expect(config.keyRing).toBe(keyRing);
            expect(config.project).toBe(project);
            expect(config.location).toBe(location);
            expect(config.keyVersion).toBe(keyVersion);
        });

        it('should create config without key version', () => {
            // Given
            const keyName = 'my-key';
            const keyRing = 'my-keyring';
            const project = 'my-project';
            const location = 'us-central1';

            // When
            const config = new GCPKeyConfig(undefined, keyName, keyRing, project, location);

            // Then
            expect(config.keyName).toBe(keyName);
            expect(config.keyRing).toBe(keyRing);
            expect(config.project).toBe(project);
            expect(config.location).toBe(location);
            expect(config.keyVersion).toBe('');
        });

        it('should handle null key version', () => {
            // Given
            const keyName = 'my-key';
            const keyRing = 'my-keyring';
            const project = 'my-project';
            const location = 'us-central1';

            // When
            const config = new GCPKeyConfig(undefined, keyName, keyRing, project, location, null);

            // Then
            expect(config.keyVersion).toBe('');
        });
    });

    describe('toString', () => {
        it('should return string representation', () => {
            // Given
            const resourceName = 'projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1';
            const config = new GCPKeyConfig(resourceName);

            // When
            const result = config.toString();

            // Then
            expect(result).toContain('my-key');
            expect(result).toContain('1');
        });
    });

    describe('toKeyName', () => {
        it('should return key name without version', () => {
            // Given
            const resourceName = 'projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1';
            const config = new GCPKeyConfig(resourceName);

            // When
            const keyName = config.toKeyName();

            // Then
            expect(keyName).toBe('projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key');
            expect(keyName).not.toContain('cryptoKeyVersions');
        });

        it('should work with multi-region locations', () => {
            // Given
            const resourceName = 'projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1';
            const config = new GCPKeyConfig(resourceName);

            // When
            const keyName = config.toKeyName();

            // Then
            expect(keyName).toBe('projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key');
        });
    });

    describe('toResourceName', () => {
        it('should return full resource name with version', () => {
            // Given
            const resourceName = 'projects/my-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key/cryptoKeyVersions/1';
            const config = new GCPKeyConfig(resourceName);

            // When
            const result = config.toResourceName();

            // Then
            expect(result).toBe(resourceName);
            expect(result).toContain('cryptoKeyVersions');
        });

        it('should include empty version when not specified', () => {
            // Given
            const config = new GCPKeyConfig(undefined, 'my-key', 'my-keyring', 'my-project', 'us-central1');

            // When
            const result = config.toResourceName();

            // Then
            expect(result).toContain('cryptoKeyVersions/');
        });
    });

    describe('GCP-specific formats', () => {
        it('should accept valid GCP project IDs', () => {
            // Given - various GCP project ID formats
            const projectIds = [
                'my-project-123',
                'prod-app',
                'test-environment-01',
                'company-dev-project'
            ];

            projectIds.forEach(projectId => {
                const resourceName = `projects/${projectId}/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1`;

                // When
                const config = new GCPKeyConfig(resourceName);

                // Then
                expect(config.project).toBe(projectId);
            });
        });

        it('should accept valid key ring names', () => {
            // Given
            const keyRings = [
                'production-keyring',
                'dev_keyring',
                'test-keyring-01',
                'my_keyring_123'
            ];

            keyRings.forEach(keyRing => {
                const resourceName = `projects/my-project/locations/us-central1/keyRings/${keyRing}/cryptoKeys/test-key/cryptoKeyVersions/1`;

                // When
                const config = new GCPKeyConfig(resourceName);

                // Then
                expect(config.keyRing).toBe(keyRing);
            });
        });

        it('should accept valid crypto key names', () => {
            // Given
            const cryptoKeys = [
                'encryption-key',
                'signing_key',
                'hsm-key-01',
                'app_encryption_key_v2'
            ];

            cryptoKeys.forEach(cryptoKey => {
                const resourceName = `projects/my-project/locations/us-central1/keyRings/test-ring/cryptoKeys/${cryptoKey}/cryptoKeyVersions/1`;

                // When
                const config = new GCPKeyConfig(resourceName);

                // Then
                expect(config.keyName).toBe(cryptoKey);
            });
        });

        it('should accept various key version formats', () => {
            // Given
            const versions = ['1', '2', '10', '100'];

            versions.forEach(version => {
                const resourceName = `projects/my-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/${version}`;

                // When
                const config = new GCPKeyConfig(resourceName);

                // Then
                expect(config.keyVersion).toBe(version);
            });
        });
    });
});
