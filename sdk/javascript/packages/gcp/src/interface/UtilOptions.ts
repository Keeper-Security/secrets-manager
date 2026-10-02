import { KeyManagementServiceClient } from '@google-cloud/kms';
import { GCPKeyConfig } from 'src/GcpKeyConfig';

export type KMSClient = InstanceType<typeof KeyManagementServiceClient>;

export interface Options {
  isAsymmetric: boolean;
  cryptoClient: KMSClient;
  keyProperties: GCPKeyConfig;
  encryptionAlgorithm: string;
  keyType: string;
  token?: string | null | undefined;
};

export interface EncryptBufferOptions extends Options {
  message: string;
};

export interface DecryptBufferOptions extends Options {
  ciphertext: Buffer;
};

export interface encryptOptions extends Options {
  message: Buffer;
};

export interface decryptOptions extends Options {
  cipherText: Buffer;
};
