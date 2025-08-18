package com.keepersecurity.secretmanager.aws.kms;

/**
 * The {@code Constants} class contains a collection of constant values used for
 * cryptographic operations
 * and configurations in the AWS KMS (Key Management Service) integration.
 * 
 */
public class Constants {
	/**
	 * Private constructor to prevent instantiation of the class.
	 */
	private Constants() {
	}

	/**
	 * Constant representing the RSA 2048-bit encryption algorithm.
	 */
	public static final String RSA_2048 = "RSA_2048";

	/**
	 * Constant representing the RSA 4096-bit encryption algorithm.
	 */
	public static final String RSA_4096 = "RSA_4096";

	/**
	 * Constant representing the default symmetric encryption algorithm.
	 */
	public static final String SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT";

	/**
	 * Constant representing the RSAES-OAEP encryption scheme with SHA-256 hashing.
	 */
	public static final String RSAES_OAEP_SHA_256 = "RSAES_OAEP_SHA_256";

	/**
	 * Constant representing the RSAES-OAEP encryption scheme with SHA-1 hashing.
	 */
	public static final String RSAES_OAEP_SHA_1 = "RSAES_OAEP_SHA_1";

	/**
	 * Constant representing the SM2 public key encryption algorithm.
	 */
	public static final String SM2PKE = "SM2PKE";

	/**
	 * Constant representing the header for a cryptographic blob.
	 */
	public static final byte[] BLOB_HEADER = { (byte) 0xFF, (byte) 0xFF };

	/**
	 * Constant representing the block size used in cryptographic operations.
	 */
	public static final int BLOCK_SIZE = 16;

	/**
	 * Constant representing the key size used in cryptographic operations.
	 */
	public static final int KEY_SIZE = 32;

	/**
	 * Constant representing the AES encryption algorithm in GCM mode with no
	 * padding.
	 */
	public static final String AES_GCM = "AES/GCM/NoPadding";

	/**
	 * Constant representing the AES encryption algorithm.
	 */
	public static final String AES = "AES";

	/**
	 * Constant representing the GCM tag length in bits.
	 */
	public static final int GCM_TAG_LENGTH = 96;

}