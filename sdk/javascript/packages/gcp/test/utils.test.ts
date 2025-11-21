// Mock GCP SDK and dependencies BEFORE importing anything
jest.mock('@google-cloud/kms', () => ({
    KeyManagementServiceClient: jest.fn(),
}));
jest.mock('fast-crc32c', () => ({
    calculate: jest.fn().mockReturnValue(12345),
}));
jest.mock('axios', () => ({
    post: jest.fn(),
}));

import { encryptBuffer, decryptBuffer } from '../src/utils';
import { GCPKeyConfig } from '../src/GcpKeyConfig';
import { Logger } from 'pino';
import axios from 'axios';

// Mock logger
const mockLogger = {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
} as unknown as Logger;

// Mock GCP key config - use real instance instead of mock
const mockKeyProperties = new GCPKeyConfig(
    undefined,
    'test-key',
    'test-ring',
    'test-project',
    'us-central1',
    '1'
);

describe('utils', () => {
    let mockCryptoClient: any;

    beforeEach(() => {
        jest.clearAllMocks();
        mockCryptoClient = {
            encrypt: jest.fn(),
            decrypt: jest.fn(),
            getPublicKey: jest.fn(),
            asymmetricDecrypt: jest.fn(),
        };
    });

    describe('encryptBuffer', () => {
        it('should encrypt a message with symmetric key successfully', async () => {
            // Given
            const message = 'test message to encrypt';
            const mockCiphertext = Buffer.from('mock-encrypted-data');

            mockCryptoClient.encrypt.mockResolvedValue([{
                ciphertext: mockCiphertext,
                ciphertextCrc32c: { value: 12345 },
                verifiedPlaintextCrc32c: true,
            }]);

            // When
            const result = await encryptBuffer({
                message,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: false,
                keyType: 'ENCRYPT_DECRYPT',
                encryptionAlgorithm: '',
                token: null,
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
            expect(mockCryptoClient.encrypt).toHaveBeenCalledTimes(1);
        });

        it('should return empty buffer when asymmetric encryption fails', async () => {
            // Given
            const message = 'test message';

            mockCryptoClient.getPublicKey.mockRejectedValue(new Error('Failed to get public key'));

            // When
            const result = await encryptBuffer({
                message,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: true,
                keyType: 'ASYMMETRIC_DECRYPT',
                encryptionAlgorithm: 'RSA_DECRYPT_OAEP_2048_SHA256',
                token: null,
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBe(0);
            expect(mockCryptoClient.getPublicKey).toHaveBeenCalledTimes(1);
        });

        it('should encrypt with raw symmetric API when token provided', async () => {
            // Given
            const message = 'test message';
            const token = 'mock-oauth-token';

            (axios.post as jest.Mock).mockResolvedValue({
                data: {
                    ciphertext: Buffer.from('encrypted').toString('base64'),
                    initializationVector: Buffer.from('123456789012').toString('base64'),
                },
            });

            // When
            const result = await encryptBuffer({
                message,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: false,
                keyType: 'RAW_ENCRYPT_DECRYPT',
                encryptionAlgorithm: '',
                token,
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
            expect(axios.post).toHaveBeenCalledTimes(1);
        });

        it('should return empty buffer when encryption fails', async () => {
            // Given
            const message = 'test message';
            mockCryptoClient.encrypt.mockRejectedValue(new Error('GCP API error'));

            // When
            const result = await encryptBuffer({
                message,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: false,
                keyType: 'ENCRYPT_DECRYPT',
                encryptionAlgorithm: '',
                token: null,
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBe(0);
        });

        it('should handle empty message', async () => {
            // Given
            const message = '';
            const mockCiphertext = Buffer.from('mock-encrypted-data');

            mockCryptoClient.encrypt.mockResolvedValue([{
                ciphertext: mockCiphertext,
                ciphertextCrc32c: { value: 12345 },
                verifiedPlaintextCrc32c: true,
            }]);

            // When
            const result = await encryptBuffer({
                message,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: false,
                keyType: 'ENCRYPT_DECRYPT',
                encryptionAlgorithm: '',
                token: null,
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
        });

        it('should handle long messages', async () => {
            // Given
            const message = 'a'.repeat(10000);
            const mockCiphertext = Buffer.from('mock-encrypted-data');

            mockCryptoClient.encrypt.mockResolvedValue([{
                ciphertext: mockCiphertext,
                ciphertextCrc32c: { value: 12345 },
                verifiedPlaintextCrc32c: true,
            }]);

            // When
            const result = await encryptBuffer({
                message,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: false,
                keyType: 'ENCRYPT_DECRYPT',
                encryptionAlgorithm: '',
                token: null,
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
        });
    });

    describe('decryptBuffer', () => {
        it('should return empty string when header is invalid', async () => {
            // Given - buffer without valid header
            const invalidBuffer = Buffer.from([0xFF, 0xFF, 0x00, 0x00]);

            // When
            const result = await decryptBuffer({
                ciphertext: invalidBuffer,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: false,
                keyType: 'ENCRYPT_DECRYPT',
                encryptionAlgorithm: '',
                token: null,
            }, mockLogger);

            // Then
            expect(result).toBe('');
        });

        it('should return empty string when buffer is too short', async () => {
            // Given - buffer that's too short
            const shortBuffer = Buffer.from([0x01]);

            // When
            const result = await decryptBuffer({
                ciphertext: shortBuffer,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: false,
                keyType: 'ENCRYPT_DECRYPT',
                encryptionAlgorithm: '',
                token: null,
            }, mockLogger);

            // Then
            expect(result).toBe('');
        });

        it('should return empty string when GCP decrypt fails', async () => {
            // Given - create a properly formatted buffer
            const header = Buffer.from([0x01, 0x00]); // BLOB_HEADER
            const encryptedKey = Buffer.from('encrypted-key-data');
            const nonce = Buffer.from('1234567890123456');
            const tag = Buffer.from('1234567890123456');
            const ciphertext = Buffer.from('encrypted-data');

            const parts = [encryptedKey, nonce, tag, ciphertext];
            const buffers = [header];

            for (const part of parts) {
                const lengthBuffer = Buffer.alloc(2);
                lengthBuffer.writeUInt16BE(part.length, 0);
                buffers.push(lengthBuffer, part);
            }

            const validBuffer = Buffer.concat(buffers);

            mockCryptoClient.decrypt.mockRejectedValue(new Error('GCP API error'));

            // When
            const result = await decryptBuffer({
                ciphertext: validBuffer,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: false,
                keyType: 'ENCRYPT_DECRYPT',
                encryptionAlgorithm: '',
                token: null,
            }, mockLogger);

            // Then
            expect(result).toBe('');
        });
    });

    describe('error handling', () => {
        it('should handle crypto client exceptions gracefully in encrypt', async () => {
            // Given
            const message = 'test message';
            mockCryptoClient.encrypt.mockImplementation(() => {
                throw new Error('Unexpected sync error');
            });

            // When
            const result = await encryptBuffer({
                message,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: false,
                keyType: 'ENCRYPT_DECRYPT',
                encryptionAlgorithm: '',
                token: null,
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBe(0);
        });

        it('should handle crypto client exceptions gracefully in decrypt', async () => {
            // Given
            const header = Buffer.from([0x01, 0x00]);
            const encryptedKey = Buffer.from('encrypted-key-data');
            const nonce = Buffer.from('1234567890123456');
            const tag = Buffer.from('1234567890123456');
            const ciphertext = Buffer.from('encrypted-data');

            const parts = [encryptedKey, nonce, tag, ciphertext];
            const buffers = [header];

            for (const part of parts) {
                const lengthBuffer = Buffer.alloc(2);
                lengthBuffer.writeUInt16BE(part.length, 0);
                buffers.push(lengthBuffer, part);
            }

            const validBuffer = Buffer.concat(buffers);

            mockCryptoClient.decrypt.mockImplementation(() => {
                throw new Error('Unexpected sync error');
            });

            // When
            const result = await decryptBuffer({
                ciphertext: validBuffer,
                cryptoClient: mockCryptoClient,
                keyProperties: mockKeyProperties,
                isAsymmetric: false,
                keyType: 'ENCRYPT_DECRYPT',
                encryptionAlgorithm: '',
                token: null,
            }, mockLogger);

            // Then
            expect(result).toBe('');
        });
    });
});
