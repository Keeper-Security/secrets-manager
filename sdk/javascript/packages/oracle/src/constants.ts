import { LoggerLogLevelOptions } from "./enum";

export const BLOB_HEADER = "\xff\xff"; // Encrypted BLOB Header: U+FFFF is a non character
export const LATIN1_ENCODING = "latin1";
export const UTF_8_ENCODING = "utf-8";
export const AES_256_GCM = "aes-256-gcm";
export const RSA_OAEP = "RSA-OAEP";
export const DEFAULT_ORACLE_CREDENTIAL_ENVIRONMENTAL_VARIABLE = "~/.oci/config";
export const MD5_HASH = "md5";
export const HEX_DIGEST = "hex";
export const DEFAULT_JSON_INDENT = 4;
export const BASE_64 = "base64";
export const DEFAULT_LOG_LEVEL = LoggerLogLevelOptions.info;