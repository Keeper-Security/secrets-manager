import { AzureSessionConfig } from '../src/AzureSessionConfig';

describe('AzureSessionConfig', () => {
    describe('constructor', () => {
        it('should create config with valid parameters', () => {
            // Given
            const tenantId = 'test-tenant-123';
            const clientId = 'test-client-456';
            const clientSecret = 'test-secret-789';

            // When
            const config = new AzureSessionConfig(tenantId, clientId, clientSecret);

            // Then
            expect(config.tenantId).toBe(tenantId);
            expect(config.clientId).toBe(clientId);
            expect(config.clientSecret).toBe(clientSecret);
        });

        it('should handle empty string values', () => {
            // When
            const config = new AzureSessionConfig('', '', '');

            // Then
            expect(config.tenantId).toBe('');
            expect(config.clientId).toBe('');
            expect(config.clientSecret).toBe('');
        });

        it('should store all provided values correctly', () => {
            // Given
            const configs = [
                ['tenant1', 'client1', 'secret1'],
                ['aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'client-guid', 'very-long-secret-key-here'],
                ['short', 'c', 's']
            ];

            configs.forEach(([tenant, client, secret]) => {
                // When
                const config = new AzureSessionConfig(tenant, client, secret);

                // Then
                expect(config.tenantId).toBe(tenant);
                expect(config.clientId).toBe(client);
                expect(config.clientSecret).toBe(secret);
            });
        });
    });

    describe('property assignment', () => {
        it('should allow modifying tenantId after creation', () => {
            // Given
            const config = new AzureSessionConfig('original-tenant', 'client', 'secret');
            const newTenantId = 'new-tenant-id';

            // When
            config.tenantId = newTenantId;

            // Then
            expect(config.tenantId).toBe(newTenantId);
            expect(config.clientId).toBe('client');
            expect(config.clientSecret).toBe('secret');
        });

        it('should allow modifying clientId after creation', () => {
            // Given
            const config = new AzureSessionConfig('tenant', 'original-client', 'secret');
            const newClientId = 'new-client-id';

            // When
            config.clientId = newClientId;

            // Then
            expect(config.tenantId).toBe('tenant');
            expect(config.clientId).toBe(newClientId);
            expect(config.clientSecret).toBe('secret');
        });

        it('should allow modifying clientSecret after creation', () => {
            // Given
            const config = new AzureSessionConfig('tenant', 'client', 'original-secret');
            const newClientSecret = 'new-secret';

            // When
            config.clientSecret = newClientSecret;

            // Then
            expect(config.tenantId).toBe('tenant');
            expect(config.clientId).toBe('client');
            expect(config.clientSecret).toBe(newClientSecret);
        });

        it('should allow setting properties to empty strings', () => {
            // Given
            const config = new AzureSessionConfig('tenant', 'client', 'secret');

            // When
            config.tenantId = '';
            config.clientId = '';
            config.clientSecret = '';

            // Then
            expect(config.tenantId).toBe('');
            expect(config.clientId).toBe('');
            expect(config.clientSecret).toBe('');
        });
    });

    describe('Azure-specific formats', () => {
        it('should accept valid Azure tenant ID formats', () => {
            // Given - various Azure tenant ID formats
            const tenantIds = [
                'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', // GUID format
                'contoso.onmicrosoft.com',               // Domain format
                'organizations',                          // Multi-tenant
                'consumers',                              // Personal Microsoft accounts
                'common'                                  // Both work and personal accounts
            ];

            tenantIds.forEach(tenantId => {
                // When
                const config = new AzureSessionConfig(tenantId, 'test-client', 'test-secret');

                // Then
                expect(config.tenantId).toBe(tenantId);
            });
        });

        it('should accept valid Azure client ID (Application ID) formats', () => {
            // Given - Azure Application (Client) IDs are GUIDs
            const clientIds = [
                'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb',
                '12345678-90ab-cdef-1234-567890abcdef',
                'ffffffff-ffff-ffff-ffff-ffffffffffff'
            ];

            clientIds.forEach(clientId => {
                // When
                const config = new AzureSessionConfig('test-tenant', clientId, 'test-secret');

                // Then
                expect(config.clientId).toBe(clientId);
            });
        });

        it('should accept various client secret formats', () => {
            // Given - Client secrets can be various formats
            const clientSecrets = [
                'simple-secret',
                'Very.Long~Secret_With-Special!Characters123',
                'aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE',
                '~Q8XYZ.123ABC-456def_789ghi'
            ];

            clientSecrets.forEach(clientSecret => {
                // When
                const config = new AzureSessionConfig('test-tenant', 'test-client', clientSecret);

                // Then
                expect(config.clientSecret).toBe(clientSecret);
            });
        });
    });
});
