export enum KeyPurpose {
  ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT",
  ASYMMETRIC_DECRYPT = "ASYMMETRIC_DECRYPT",
  CRYPTO_KEY_PURPOSE_UNSPECIFIED = "CRYPTO_KEY_PURPOSE_UNSPECIFIED",
  ASYMMETRIC_SIGN = "ASYMMETRIC_SIGN",
  RAW_ENCRYPT_DECRYPT = "RAW_ENCRYPT_DECRYPT",
  MAC = "MAC"
}

export enum EncryptionAlgorithmSpec {
  SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT",
  RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256"
}

export enum LoggerLogLevelOptions {
  trace = "trace",
  debug = "debug",
  info = "info",
  warn = "warn",
  error = "error",
  fatal = "fatal",
}