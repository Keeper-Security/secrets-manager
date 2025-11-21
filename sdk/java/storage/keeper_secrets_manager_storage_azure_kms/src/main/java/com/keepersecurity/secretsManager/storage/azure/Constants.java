package com.keepersecurity.secretsManager.storage.azure;

/**
 * The {@code Constants} class defines a set of constant values used throughout
 * the application.
 * These constants include cryptographic configurations, file-related constants,
 * and environment variable keys.
 */
public class Constants {

	private Constants() {
		// Prevent instantiation
	}
	/**
	 * The header used for identifying encrypted blobs.
	 */
	public static final byte[] BLOB_HEADER = { (byte) 0xFF, (byte) 0xFF };

	/**
	 * The block size (in bytes) used for cryptographic operations.
	 */
	public static final int BLOCK_SIZE = 16;

	/**
	 * The key size (in bytes) used for cryptographic operations.
	 */
	public static final int KEY_SIZE = 32;

	/**
	 * The algorithm and mode used for AES encryption with GCM (Galois/Counter
	 * Mode).
	 */
	public static final String AES_GCM = "AES/GCM/NoPadding";

	/**
	 * The AES encryption algorithm.
	 */
	public static final String AES = "AES";

	/**
	 * The tag length (in bits) used for GCM authentication.
	 */
	public static final int GCM_TAG_LENGTH = 96;

	/**
	 * The environment variable key for the configuration file location.
	 */
	public static final String KSM_CONFIG_FILE = "KSM_CONFIG_FILE";

	/**
	 * The environment variable key for the Azure Key Vault key ID.
	 */
	public static final String KSM_AZ_KEY_ID = "KSM_AZ_KEY_ID";

	/**
	 * The MD5 hashing algorithm identifier.
	 */
	public static final String MD5 = "MD5";
}