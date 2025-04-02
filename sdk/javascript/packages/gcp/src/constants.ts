import { KeyPurpose, LoggerLogLevelOptions } from "./enum";
import { constants } from "crypto";

export const supportedKeyPurpose: string[] = [
  KeyPurpose.RAW_ENCRYPT_DECRYPT,
  KeyPurpose.ENCRYPT_DECRYPT,
  KeyPurpose.ASYMMETRIC_DECRYPT,
];

export const BLOB_HEADER = "\xff\xff"; // Encrypted BLOB Header: U+FFFF is a non character
export const LATIN1_ENCODING = "latin1";
export const UTF_8_ENCODING = "utf-8";
export const AES_256_GCM = "aes-256-gcm";
export const MD5_HASH = "md5";
export const HEX_DIGEST = "hex";
export const DEFAULT_JSON_INDENT = 4;
export const OAEP_PADDINg = constants.RSA_PKCS1_OAEP_PADDING;
export const SHA_256 = 'sha256';
export const SHA_1 = 'sha1';
export const SHA_512 = 'sha512';
export const DEFAULT_LOG_LEVEL = LoggerLogLevelOptions.info;