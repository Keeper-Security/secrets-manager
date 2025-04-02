import { KeyManagementServiceClient } from '@google-cloud/kms';
import { GCPKeyConfig } from 'src/GcpKeyConfig';

export type KMSClient = InstanceType<typeof KeyManagementServiceClient>;

export interface Options {
  isAsymmetric: boolean;
  cryptoClient: KMSClient;
  keyProperties: GCPKeyConfig;
  encryptionAlgorithm: string;
};

export interface BufferOptions extends Options {
  keyType: string;
};

export interface EncryptBufferOptions extends BufferOptions {
  message: string;
};

export interface DecryptBufferOptions extends BufferOptions {
  ciphertext: Buffer;
};

export interface encryptOptions extends Options {
  message: Buffer;
};

export interface decryptOptions extends Options {
  cipherText: Buffer;
};
