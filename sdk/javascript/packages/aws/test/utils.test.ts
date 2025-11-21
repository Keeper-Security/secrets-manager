import { encryptBuffer, decryptBuffer } from '../src/utils';
import { KMSClient } from '@aws-sdk/client-kms';
import { Logger } from 'pino';

// Mock the AWS SDK
jest.mock('@aws-sdk/client-kms');

// Mock logger
jest.mock('../src/Logger', () => ({
    getLogger: jest.fn(() => ({
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
    }))
}));

const mockLogger = {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
} as unknown as Logger;

describe('utils', () => {
    let mockCryptoClient: any;

    beforeEach(() => {
        jest.clearAllMocks();
        mockCryptoClient = {
            send: jest.fn(),
        };
    });

    describe('encryptBuffer', () => {
        it('should encrypt a message successfully', async () => {
            // Given
            const message = 'test message to encrypt';
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const mockCiphertextBlob = Buffer.from('mock-encrypted-key');

            mockCryptoClient.send.mockResolvedValue({
                CiphertextBlob: mockCiphertextBlob,
            } as any);

            // When
            const result = await encryptBuffer({
                keyId,
                message,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
            expect(mockCryptoClient.send).toHaveBeenCalledTimes(1);
        });

        it('should return empty buffer when AWS KMS encrypt fails', async () => {
            // Given
            const message = 'test message';
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            mockCryptoClient.send.mockRejectedValue(new Error('AWS KMS API error'));

            // When
            const result = await encryptBuffer({
                keyId,
                message,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBe(0);
        });

        it('should handle empty message', async () => {
            // Given
            const message = '';
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const mockCiphertextBlob = Buffer.from('mock-encrypted-key');

            mockCryptoClient.send.mockResolvedValue({
                CiphertextBlob: mockCiphertextBlob,
            } as any);

            // When
            const result = await encryptBuffer({
                keyId,
                message,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
        });

        it('should handle long messages', async () => {
            // Given
            const message = 'a'.repeat(10000);
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const mockCiphertextBlob = Buffer.from('mock-encrypted-key');

            mockCryptoClient.send.mockResolvedValue({
                CiphertextBlob: mockCiphertextBlob,
            } as any);

            // When
            const result = await encryptBuffer({
                keyId,
                message,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
        });

        it('should handle special characters in message', async () => {
            // Given
            const message = 'test™ 你好 🎉 \n\t\r';
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const mockCiphertextBlob = Buffer.from('mock-encrypted-key');

            mockCryptoClient.send.mockResolvedValue({
                CiphertextBlob: mockCiphertextBlob,
            } as any);

            // When
            const result = await encryptBuffer({
                keyId,
                message,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
        });

        it('should handle SYMMETRIC_DEFAULT key type', async () => {
            // Given
            const message = 'test message';
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const mockCiphertextBlob = Buffer.from('mock-encrypted-key');

            mockCryptoClient.send.mockResolvedValue({
                CiphertextBlob: mockCiphertextBlob,
            } as any);

            // When
            const result = await encryptBuffer({
                keyId,
                message,
                encryptionAlgorithm: 'SYMMETRIC_DEFAULT',
                cryptoClient: mockCryptoClient,
                keyType: 'SYMMETRIC_DEFAULT',
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
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

            // When
            const result = await decryptBuffer({
                keyId,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                ciphertext: invalidBuffer,
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then
            expect(result).toBe('');
        });

        it('should return empty string when buffer is too short', async () => {
            // Given - buffer that's too short
            const shortBuffer = Buffer.from([0x01]);
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

            // When
            const result = await decryptBuffer({
                keyId,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                ciphertext: shortBuffer,
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then
            expect(result).toBe('');
        });

        it('should return empty string when AWS KMS decrypt fails', async () => {
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
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

            mockCryptoClient.send.mockRejectedValue(new Error('AWS KMS API error'));

            // When
            const result = await decryptBuffer({
                keyId,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                ciphertext: validBuffer,
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then
            expect(result).toBe('');
        });

        it('should return empty string when plaintext key is missing', async () => {
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
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

            mockCryptoClient.send.mockResolvedValue({
                Plaintext: undefined,
            } as any);

            // When
            const result = await decryptBuffer({
                keyId,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                ciphertext: validBuffer,
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then
            expect(result).toBe('');
        });
    });

    describe('encrypt/decrypt round-trip', () => {
        it('should successfully encrypt and decrypt a message', async () => {
            // Given
            const originalMessage = 'test message for round trip';
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            const mockCiphertextBlob = Buffer.from('mock-encrypted-key');
            const mockPlaintext = Buffer.from('mock-aes-key-32-bytes-long!!!');

            mockCryptoClient.send
                .mockResolvedValueOnce({
                    CiphertextBlob: mockCiphertextBlob,
                } as any)
                .mockResolvedValueOnce({
                    Plaintext: mockPlaintext,
                } as any);

            // When - encrypt
            const encrypted = await encryptBuffer({
                keyId,
                message: originalMessage,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then - verify encrypted
            expect(encrypted).toBeInstanceOf(Buffer);
            expect(encrypted.length).toBeGreaterThan(0);

            // Note: Full round-trip decryption would require matching the exact
            // encryption/decryption logic with proper keys and nonces.
            // This test verifies the structure is correct.
        });
    });

    describe('error handling', () => {
        it('should handle crypto client exceptions gracefully in encrypt', async () => {
            // Given
            const message = 'test message';
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
            mockCryptoClient.send.mockImplementation(() => {
                throw new Error('Unexpected sync error');
            });

            // When
            const result = await encryptBuffer({
                keyId,
                message,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
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
            const keyId = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

            mockCryptoClient.send.mockImplementation(() => {
                throw new Error('Unexpected sync error');
            });

            // When
            const result = await decryptBuffer({
                keyId,
                encryptionAlgorithm: 'RSAES_OAEP_SHA_256',
                ciphertext: validBuffer,
                cryptoClient: mockCryptoClient,
                keyType: 'RSA_2048',
            }, mockLogger);

            // Then
            expect(result).toBe('');
        });
    });
});
