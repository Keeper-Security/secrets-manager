export enum EncryptionAlgorithmEnum {
  SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT",
  RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256",
  RSAES_OAEP_SHA_1 = "RSAES_OAEP_SHA_1",
  SM2PKE = "SM2PKE",
}

export enum KeySpecEnum {
  RSA_2048 = "RSA_2048",
  RSA_3072 = "RSA_3072",
  RSA_4096 = "RSA_4096",
  ECC_NIST_P256 = "ECC_NIST_P256",
  ECC_NIST_P384 = "ECC_NIST_P384",
  ECC_NIST_P521 = "ECC_NIST_P521",
  ECC_SECG_P256K1 = "ECC_SECG_P256K1",
  SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT",
  HMAC_224 = "HMAC_224",
  HMAC_256 = "HMAC_256",
  HMAC_384 = "HMAC_384",
  HMAC_512 = "HMAC_512",
  SM2 = "SM2",
}

export enum LoggerLogLevelOptions {
  trace = "trace",
  debug = "debug",
  info = "info",
  warn = "warn",
  error = "error",
  fatal = "fatal",
}