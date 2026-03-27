// Mock the OCI SDK and native modules BEFORE importing anything
jest.mock('oci-keymanagement', () => ({
    KmsCryptoClient: jest.fn(),
}));
jest.mock('oci-common', () => ({
    ConfigFileAuthenticationDetailsProvider: jest.fn(),
}));
jest.mock('@aws-crypto/crc32c', () => ({
    crc32c: jest.fn().mockReturnValue(12345),
}));

import { encryptBuffer, decryptBuffer } from '../src/utils';
import { KmsCryptoClient } from 'oci-keymanagement';
import { Logger } from 'pino';

// Mock logger
const mockLogger = {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
} as unknown as Logger;

describe('utils', () => {
    let mockCryptoClient: jest.Mocked<KmsCryptoClient>;

    beforeEach(() => {
        jest.clearAllMocks();
        mockCryptoClient = {
            encrypt: jest.fn(),
            decrypt: jest.fn(),
        } as any;
    });

    describe('encryptBuffer', () => {
        it('should encrypt a message successfully', async () => {
            // Given
            const message = 'test message to encrypt';
            const keyId = 'ocid1.key.oc1.phx.example';
            const mockCiphertext = 'mock-encrypted-key-base64';

            mockCryptoClient.encrypt.mockResolvedValue({
                encryptedData: {
                    ciphertext: mockCiphertext,
                },
            } as any);

            // When
            const result = await encryptBuffer({
                keyId,
                message,
                cryptoClient: mockCryptoClient,
                keyVersionId: '',
                isAsymmetric: false,
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
            expect(mockCryptoClient.encrypt).toHaveBeenCalledTimes(1);
            expect(mockCryptoClient.encrypt).toHaveBeenCalledWith(
                expect.objectContaining({
                    encryptDataDetails: expect.objectContaining({
                        keyId,
                        plaintext: expect.any(String),
                    }),
                })
            );
        });

        it('should throw when OCI encrypt fails', async () => {
            // Given
            const message = 'test message';
            mockCryptoClient.encrypt.mockRejectedValue(new Error('OCI API error'));

            // When / Then
            await expect(encryptBuffer({
                keyId: 'ocid1.key.oc1.phx.example',
                message,
                cryptoClient: mockCryptoClient,
                keyVersionId: '',
                isAsymmetric: false,
            }, mockLogger)).rejects.toThrow('OCI API error');
        });

        it('should handle empty message', async () => {
            // Given
            const message = '';
            const mockCiphertext = 'mock-encrypted-key-base64';

            mockCryptoClient.encrypt.mockResolvedValue({
                encryptedData: {
                    ciphertext: mockCiphertext,
                },
            } as any);

            // When
            const result = await encryptBuffer({
                keyId: 'ocid1.key.oc1.phx.example',
                message,
                cryptoClient: mockCryptoClient,
                keyVersionId: '',
                isAsymmetric: false,
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
        });

        it('should handle long messages', async () => {
            // Given
            const message = 'a'.repeat(10000);
            const mockCiphertext = 'mock-encrypted-key-base64';

            mockCryptoClient.encrypt.mockResolvedValue({
                encryptedData: {
                    ciphertext: mockCiphertext,
                },
            } as any);

            // When
            const result = await encryptBuffer({
                keyId: 'ocid1.key.oc1.phx.example',
                message,
                cryptoClient: mockCryptoClient,
                keyVersionId: '',
                isAsymmetric: false,
            }, mockLogger);

            // Then
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeGreaterThan(0);
        });

        it('should include keyVersionId when provided', async () => {
            // Given
            const keyVersionId = 'version-123';
            const mockCiphertext = 'mock-encrypted-key-base64';

            mockCryptoClient.encrypt.mockResolvedValue({
                encryptedData: {
                    ciphertext: mockCiphertext,
                },
            } as any);

            // When
            await encryptBuffer({
                keyId: 'ocid1.key.oc1.phx.example',
                message: 'test',
                cryptoClient: mockCryptoClient,
                keyVersionId,
                isAsymmetric: false,
            }, mockLogger);

            // Then
            expect(mockCryptoClient.encrypt).toHaveBeenCalledWith(
                expect.objectContaining({
                    encryptDataDetails: expect.objectContaining({
                        keyVersionId,
                    }),
                })
            );
        });

        it('should use RSA-OAEP-SHA256 for asymmetric keys', async () => {
            // Given
            const mockCiphertext = 'mock-encrypted-key-base64';

            mockCryptoClient.encrypt.mockResolvedValue({
                encryptedData: {
                    ciphertext: mockCiphertext,
                },
            } as any);

            // When
            await encryptBuffer({
                keyId: 'ocid1.key.oc1.phx.example',
                message: 'test',
                cryptoClient: mockCryptoClient,
                keyVersionId: '',
                isAsymmetric: true,
            }, mockLogger);

            // Then
            expect(mockCryptoClient.encrypt).toHaveBeenCalledWith(
                expect.objectContaining({
                    encryptDataDetails: expect.objectContaining({
                        encryptionAlgorithm: 'RSA_OAEP_SHA_256',
                    }),
                })
            );
        });
    });

    describe('decryptBuffer', () => {
        it('should throw when header is invalid', async () => {
            // Given - buffer without valid header
            const invalidBuffer = Buffer.from([0xFF, 0xFF, 0x00, 0x00]);

            // When / Then
            await expect(decryptBuffer({
                keyId: 'ocid1.key.oc1.phx.example',
                ciphertext: invalidBuffer,
                cryptoClient: mockCryptoClient,
                keyVersionId: '',
                isAsymmetric: false,
            }, mockLogger)).rejects.toThrow();
        });

        it('should throw when buffer is too short', async () => {
            // Given - buffer that's too short
            const shortBuffer = Buffer.from([0x01]);

            // When / Then
            await expect(decryptBuffer({
                keyId: 'ocid1.key.oc1.phx.example',
                ciphertext: shortBuffer,
                cryptoClient: mockCryptoClient,
                keyVersionId: '',
                isAsymmetric: false,
            }, mockLogger)).rejects.toThrow();
        });

        it('should throw when OCI decrypt fails', async () => {
            // Given - create a properly formatted buffer
            const header = Buffer.from([0xFF, 0xFF]); // BLOB_HEADER
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

            mockCryptoClient.decrypt.mockRejectedValue(new Error('OCI API error'));

            // When / Then
            await expect(decryptBuffer({
                keyId: 'ocid1.key.oc1.phx.example',
                ciphertext: validBuffer,
                cryptoClient: mockCryptoClient,
                keyVersionId: '',
                isAsymmetric: false,
            }, mockLogger)).rejects.toThrow('OCI API error');
        });
    });

    describe('error handling', () => {
        it('should throw on crypto client exceptions in encrypt', async () => {
            // Given
            const message = 'test message';
            mockCryptoClient.encrypt.mockImplementation(() => {
                throw new Error('Unexpected sync error');
            });

            // When / Then
            await expect(encryptBuffer({
                keyId: 'ocid1.key.oc1.phx.example',
                message,
                cryptoClient: mockCryptoClient,
                keyVersionId: '',
                isAsymmetric: false,
            }, mockLogger)).rejects.toThrow('Unexpected sync error');
        });

        it('should throw on crypto client exceptions in decrypt', async () => {
            // Given
            const header = Buffer.from([0xFF, 0xFF]); // BLOB_HEADER
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

            // When / Then
            await expect(decryptBuffer({
                keyId: 'ocid1.key.oc1.phx.example',
                ciphertext: validBuffer,
                cryptoClient: mockCryptoClient,
                keyVersionId: '',
                isAsymmetric: false,
            }, mockLogger)).rejects.toThrow('Unexpected sync error');
        });
    });
});
