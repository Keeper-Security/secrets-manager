package com.keepersecurity.secretmanager.oracle.kv;

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

import com.oracle.bmc.Region;

/**
 * The {@code OracleSessionConfig} class represents a configuration for an
 * oracle session configuration,
 * containing the oracle key vault id, region, key Id, version and end point.
 * 
 */
public class OracleSessionConfig {

	private String cryptoEndpoint;
	private String vaultId;
	private String keyId;
	private String keyVersionId;
	private String configPath;
	private String managementEndpoint;
	private Region region;

	/**
	 * Constructor to initialize oracle key vault configuration
	 * 
	 * @param configPath          : configuration Path
	 * @param cryptoEndpoint:     oracle key vault cryptoEndpoint
	 * @param managementEndpoint: managementEndpoint
	 * @param vaultId:            vaultId
	 * @param keyId:              keyId
	 * @param keyVersionId:       keyVersionId
	 * @param region:             region
	 */
	public OracleSessionConfig(String configPath, String cryptoEndpoint, String managementEndpoint, String vaultId,
			String keyId, String keyVersionId, Region region) {
		super();
		this.configPath = configPath;
		this.cryptoEndpoint = cryptoEndpoint;
		this.vaultId = vaultId;
		this.keyId = keyId;
		this.keyVersionId = keyVersionId;
		this.managementEndpoint = managementEndpoint;
		this.region = region;
	}

	/**
	 * Returns the config path
	 * 
	 * @return The config path in string format
	 */
	public String getConfigPath() {
		return this.configPath;
	}

	/**
	 * Set the config path
	 * 
	 * @param configPath: config path
	 */
	public void setConfigPath(String configPath) {
		this.configPath = configPath;
	}

	/**
	 * Get the oracle Crypto Endpoint
	 * 
	 * @return cryptoEndpoint
	 */
	public String getCryptoEndpoint() {
		return cryptoEndpoint;
	}

	/**
	 * Set oracle Crypto Endpoint
	 * 
	 * @param cryptoEndpoint: Crypto Endpoint
	 */
	public void setCryptoEndpoint(String cryptoEndpoint) {
		this.cryptoEndpoint = cryptoEndpoint;
	}

	/**
	 * Return vault ID
	 * 
	 * @return vaultId in string format
	 */
	public String getVaultId() {
		return vaultId;
	}

	/**
	 * Set oracle vault ID
	 * 
	 * @param vaultId: vault ID
	 */
	public void setVaultId(String vaultId) {
		this.vaultId = vaultId;
	}

	/**
	 * Return Key ID
	 * 
	 * @return keyId in string format
	 */
	public String getKeyId() {
		return keyId;
	}

	/**
	 * Set Key ID
	 * 
	 * @param keyId: Key ID
	 */
	public void setKeyId(String keyId) {
		this.keyId = keyId;
	}

	/**
	 * Get Key Verion ID
	 * 
	 * @return keyVersionId in string format
	 */
	public String getKeyVersionId() {
		return keyVersionId;
	}

	/**
	 * Set Key Version ID
	 * 
	 * @param keyVersionId: Key VersionID
	 */
	public void setKeyVersionId(String keyVersionId) {
		this.keyVersionId = keyVersionId;
	}

	/**
	 * Set Management Endpoint
	 * 
	 * @param managementEndpoint: Management Endpoint
	 */
	public void setManagementEndpoint(String managementEndpoint) {
		this.managementEndpoint = managementEndpoint;
	}

	/**
	 * Get Management Endpoint
	 * 
	 * @return managementEndpoint in string format
	 */
	public String getManagementEndpoint() {
		return managementEndpoint;
	}

	/**
	 * Get Region
	 * 
	 * @return region in string format
	 */
	public Region getRegion() {
		return region;
	}

	/**
	 * Set Region
	 * 
	 * @param region: Region
	 */
	public void setRegion(Region region) {
		this.region = region;
	}
}
