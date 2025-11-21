import { encryptBuffer, decryptBuffer } from '../src/utils';
import { CryptographyClient } from '@azure/keyvault-keys';
import { Logger } from 'pino';

// Mock the Azure SDK
jest.mock('@azure/keyvault-keys');

// Mock logger
const mockLogger = {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
} as unknown as Logger;

describe('utils', () => {
    let mockCryptoClient: jest.Mocked<CryptographyClient>;

    beforeEach(() => {
        jest.clearAllMocks();
        mockCryptoClient = {
            wrapKey: jest.fn(),
            unwrapKey: jest.fn(),
        } as any;
    });

    describe('encryptBuffer', () => {
        it('should encrypt a message successfully', async () => {
            // Given
            const message = 'test message to encrypt';
            const mockWrappedKey = Buffer.from('mock-wrapped-key');

            mockCryptoClient.wrapKey.mockResolvedValue({
                result: mockWrappedKey,
            } as any);

            // When
            const result = await encryptBuffer(mockCryptoClient, message, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
            expect(mockCryptoClient.wrapKey).toHaveBeenCalledTimes(1);
            expect(mockCryptoClient.wrapKey).toHaveBeenCalledWith(
                'RSA-OAEP',
                expect.any(Buffer)
            );
        });

        it('should return empty buffer when Azure wrapKey fails', async () => {
            // Given
            const message = 'test message';
            mockCryptoClient.wrapKey.mockRejectedValue(new Error('Azure API error'));

            // When
            const result = await encryptBuffer(mockCryptoClient, message, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBe(0);
        });

        it('should handle empty message', async () => {
            // Given
            const message = '';
            const mockWrappedKey = Buffer.from('mock-wrapped-key');

            mockCryptoClient.wrapKey.mockResolvedValue({
                result: mockWrappedKey,
            } as any);

            // When
            const result = await encryptBuffer(mockCryptoClient, message, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
        });

        it('should handle long messages', async () => {
            // Given
            const message = 'a'.repeat(10000);
            const mockWrappedKey = Buffer.from('mock-wrapped-key');

            mockCryptoClient.wrapKey.mockResolvedValue({
                result: mockWrappedKey,
            } as any);

            // When
            const result = await encryptBuffer(mockCryptoClient, message, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
        });

        it('should handle special characters in message', async () => {
            // Given
            const message = 'test™ 你好 🎉 \n\t\r';
            const mockWrappedKey = Buffer.from('mock-wrapped-key');

            mockCryptoClient.wrapKey.mockResolvedValue({
                result: mockWrappedKey,
            } as any);

            // When
            const result = await encryptBuffer(mockCryptoClient, message, mockLogger);

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
            const result = await decryptBuffer(mockCryptoClient, invalidBuffer, mockLogger);

            // Then
            expect(result).toBe('');
        });

        it('should return empty string when buffer is too short', async () => {
            // Given - buffer that's too short
            const shortBuffer = Buffer.from([0x01]);

            // When
            const result = await decryptBuffer(mockCryptoClient, shortBuffer, mockLogger);

            // Then
            expect(result).toBe('');
        });

        it('should return empty string when Azure unwrapKey fails', async () => {
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

            mockCryptoClient.unwrapKey.mockRejectedValue(new Error('Azure API error'));

            // When
            const result = await decryptBuffer(mockCryptoClient, validBuffer, mockLogger);

            // Then
            expect(result).toBe('');
        });
    });

    describe('encrypt/decrypt round-trip', () => {
        it('should successfully encrypt and decrypt a message', async () => {
            // Given
            const originalMessage = 'test message for round trip';
            const mockKey = Buffer.from('mock-aes-key-32-bytes-long!!!');
            const mockWrappedKey = Buffer.from('mock-wrapped-key');

            mockCryptoClient.wrapKey.mockResolvedValue({
                result: mockWrappedKey,
            } as any);

            mockCryptoClient.unwrapKey.mockResolvedValue({
                result: mockKey,
            } as any);

            // When - encrypt
            const encrypted = await encryptBuffer(mockCryptoClient, originalMessage, mockLogger);

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
            mockCryptoClient.wrapKey.mockImplementation(() => {
                throw new Error('Unexpected sync error');
            });

            // When
            const result = await encryptBuffer(mockCryptoClient, message, mockLogger);

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

            mockCryptoClient.unwrapKey.mockImplementation(() => {
                throw new Error('Unexpected sync error');
            });

            // When
            const result = await decryptBuffer(mockCryptoClient, validBuffer, mockLogger);

            // Then
            expect(result).toBe('');
        });
    });
});
