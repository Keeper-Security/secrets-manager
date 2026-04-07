import { KMSClient, EncryptionAlgorithmSpec } from "@aws-sdk/client-kms";

export interface BufferOptions {
  keyId: string;
  encryptionAlgorithm: EncryptionAlgorithmSpec;
  cryptoClient: KMSClient;
  keyType: string;
}
export interface EncryptBufferOptions extends BufferOptions {
  message: string;
};

export interface DecryptBufferOptions extends BufferOptions {
  ciphertext: Buffer;
};