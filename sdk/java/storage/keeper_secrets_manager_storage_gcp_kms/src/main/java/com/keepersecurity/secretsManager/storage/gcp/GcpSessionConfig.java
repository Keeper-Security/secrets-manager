package com.keepersecurity.secretsManager.storage.gcp;

/*
*  _  __
* | |/ /___ ___ _ __  ___ _ _ (R)
* | ' </ -_) -_) '_ \/ -_) '_|
* |_|\_\___\___| .__/\___|_|
*              |_|
*
* Keeper Secrets Manager
* Copyright 2025 Keeper Security Inc.
* Contact: sm@keepersecurity.com
*/

/**
 * The {@code GcpSessionConfig} class represents the configuration
 * settings for a Google Cloud Platform (GCP) session.
 * It includes parameters such as project ID, location, key ring,
 * key ID, key version, and credentials path.
 */
public class GcpSessionConfig {

	private String location;
	private String keyRing;
	private String keyId;
	private String projectId;
	private String keyVersion;
	private String credentialsPath;

	/**
	 * Constructs a new {@code GcpSessionConfig} object with the specified
	 * parameters.
	 *
	 * @param projectId       The GCP project ID.
	 * @param location        The location of the GCP resources.
	 * @param keyRing         The key ring name in GCP.
	 * @param keyId           The key ID in the key ring.
	 * @param keyVersion      The version of the key.
	 * @param credentialsPath The file path to the GCP credentials.
	 */
	public GcpSessionConfig(String projectId, String location, String keyRing, String keyId, String keyVersion,
			String credentialsPath) {
		super();
		this.location = location;
		this.keyRing = keyRing;
		this.keyId = keyId;
		this.projectId = projectId;
		this.keyVersion = keyVersion;
		this.credentialsPath = credentialsPath;
	}

	/**
	 * Gets the GCP project ID.
	 *
	 * @return The project ID.
	 */
	public String getProjectId() {
		return projectId;
	}

	/**
	 * Sets the GCP project ID.
	 *
	 * @param projectId The project ID to set.
	 */
	public void setProjectId(String projectId) {
		this.projectId = projectId;
	}

	/**
	 * Gets the location of the GCP resources.
	 *
	 * @return The location.
	 */
	public String getLocation() {
		return location;
	}

	/**
	 * Sets the location of the GCP resources.
	 *
	 * @param location The location to set.
	 */
	public void setLocation(String location) {
		this.location = location;
	}

	/**
	 * Gets the key ring name in GCP.
	 *
	 * @return The key ring name.
	 */
	public String getKeyRing() {
		return keyRing;
	}

	/**
	 * Sets the key ring name in GCP.
	 *
	 * @param keyRing The key ring name to set.
	 */
	public void setKeyRing(String keyRing) {
		this.keyRing = keyRing;
	}

	/**
	 * Gets the key ID in the key ring.
	 *
	 * @return The key ID.
	 */
	public String getKeyId() {
		return keyId;
	}

	/**
	 * Sets the key ID in the key ring.
	 *
	 * @param keyId The key ID to set.
	 */
	public void setKeyId(String keyId) {
		this.keyId = keyId;
	}

	/**
	 * Gets the version of the key.
	 *
	 * @return The key version.
	 */
	public String getKeyVersion() {
		return keyVersion;
	}

	/**
	 * Sets the version of the key.
	 *
	 * @param keyVersion The key version to set.
	 */
	public void setKeyVersion(String keyVersion) {
		this.keyVersion = keyVersion;
	}

	/**
	 * Gets the file path to the GCP credentials.
	 *
	 * @return The credentials file path.
	 */
	public String getCredentialsPath() {
		return credentialsPath;
	}

	/**
	 * Sets the file path to the GCP credentials.
	 *
	 * @param credentialsPath The credentials file path to set.
	 */
	public void setCredentialsPath(String credentialsPath) {
		this.credentialsPath = credentialsPath;
	}
}

/**
 * The {@code EncryptResponse} class represents the response
 * of an encryption operation, including the ciphertext and
 * initialization vector.
 */
class EncryptResponse {

	private String ciphertext;
	private String initializeVector;

	/**
	 * Constructs a new {@code EncryptResponse} object with the specified
	 * ciphertext and initialization vector.
	 *
	 * @param ciphertext       The encrypted text.
	 * @param initializeVector The initialization vector used in encryption.
	 */
	public EncryptResponse(String ciphertext, String initializeVector) {
		this.ciphertext = ciphertext;
		this.initializeVector = initializeVector;
	}

	/**
	 * Gets the encrypted text (ciphertext).
	 *
	 * @return The ciphertext.
	 */
	public String getCiphertext() {
		return ciphertext;
	}

	/**
	 * Sets the encrypted text (ciphertext).
	 *
	 * @param ciphertext The ciphertext to set.
	 */
	public void setCiphertext(String ciphertext) {
		this.ciphertext = ciphertext;
	}

	/**
	 * Gets the initialization vector used in encryption.
	 *
	 * @return The initialization vector.
	 */
	public String getInitializeVector() {
		return initializeVector;
	}

	/**
	 * Sets the initialization vector used in encryption.
	 *
	 * @param initializeVector The initialization vector to set.
	 */
	public void setInitializeVector(String initializeVector) {
		this.initializeVector = initializeVector;
	}
}