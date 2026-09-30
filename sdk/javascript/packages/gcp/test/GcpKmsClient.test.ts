// Mock Logger BEFORE importing anything
jest.mock('../src/Logger', () => ({
    getLogger: jest.fn().mockReturnValue({
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
    }),
}));

jest.mock('@google-cloud/kms', () => ({
    KeyManagementServiceClient: jest.fn().mockImplementation(() => ({
        auth: {
            getAccessToken: jest.fn().mockResolvedValue('test-access-token'),
        },
    })),
}));

import { GCPKSMClient } from '../src/GcpKmsClient';

describe('GCPKSMClient.getToken', () => {
    it('returns an access token on the default (Application Default Credentials) construction path', async () => {
        // Given
        const client = new GCPKSMClient();

        // When
        const token = await client.getToken();

        // Then
        expect(token).toBe('test-access-token');
    });
});
