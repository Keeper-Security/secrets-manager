package com.keepersecurity.secretsManager.storage.gcp;

/**
 * The {@code Constants} class defines a set of constants used for cryptographic
 * operations
 * and configurations in the application. These constants include key types,
 * encryption
 * algorithms, and other related parameters.
 */
public class Constants {
	/**
	 * Private constructor to prevent instantiation of the class.
	 */
	private Constants() {
		// Prevent instantiation
	}

	/** RSA key type with a 2048-bit key size. */
	public static final String RSA_2048 = "RSA_2048";

	/** RSA key type with a 4096-bit key size. */
	public static final String RSA_4096 = "RSA_4096";

	/** Default symmetric encryption algorithm. */
	public static final String SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT";

	/** RSA encryption scheme using OAEP with SHA-256. */
	public static final String RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256";

	/** RSA encryption scheme using OAEP with SHA-1. */
	public static final String RSAES_OAEP_SHA_1 = "RSAES_OAEP_SHA_1";

	/** SM2 public key encryption algorithm. */
	public static final String SM2PKE = "SM2PKE";

	/** Header bytes for identifying a binary blob. */
	public static final byte[] BLOB_HEADER = { (byte) 0xFF, (byte) 0xFF };

	/** Block size used in cryptographic operations, in bytes. */
	public static final int BLOCK_SIZE = 16;

	/** Key size used in cryptographic operations, in bytes. */
	public static final int KEY_SIZE = 32;

	/** AES encryption algorithm with GCM mode and no padding. */
	public static final String AES_GCM = "AES/GCM/NoPadding";

	/** AES encryption algorithm. */
	public static final String AES = "AES";

	/** Tag length for GCM mode, in bits. */
	public static final int GCM_TAG_LENGTH = 96;

	/** Add Additional Authenticate Data in bytes. */
	public static final byte[] additionalAuthenticatedData = "KeeperSecurity".getBytes();

	/** Cloud API URL */
	public static final String CLOUD_API_URL = "https://www.googleapis.com/auth/cloud-platform";
}