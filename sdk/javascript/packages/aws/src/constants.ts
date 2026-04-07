import { KeySpecEnum, LoggerLogLevelOptions } from "./enum";

export const supportedKeySpecs: string[] = [
  KeySpecEnum.RSA_2048,
  KeySpecEnum.RSA_4096,
  KeySpecEnum.RSA_3072,
  KeySpecEnum.SYMMETRIC_DEFAULT,
];

export const BLOB_HEADER = "\xff\xff"; // Encrypted BLOB Header: U+FFFF is a non character
export const LATIN1_ENCODING = "latin1";
export const UTF_8_ENCODING = "utf-8";
export const AES_256_GCM = "aes-256-gcm";
export const RSA_OAEP = "RSA-OAEP";
export const DEFAULT_AWS_CREDENTIAL_ENVIRONMENTAL_VARIABLE = "KSM_AWS_KEY_ID";
export const MD5_HASH = "md5";
export const HEX_DIGEST = "hex";
export const DEFAULT_LOG_LEVEL = LoggerLogLevelOptions.info;
export const DEFAULT_JSON_INDENT = 4;