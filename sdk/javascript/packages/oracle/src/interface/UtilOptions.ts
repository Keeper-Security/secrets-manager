import { KmsCryptoClient } from "oci-keymanagement";

export interface BufferOptions {
  keyId: string;
  cryptoClient: KmsCryptoClient;
  keyVersionId?: string;
  isAsymmetric: boolean;
}
export interface EncryptBufferOptions extends BufferOptions {
  message: string;
};

export interface DecryptBufferOptions extends BufferOptions {
  ciphertext: Buffer;
};
