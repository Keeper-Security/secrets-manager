package com.keepersecurity.secretmanager.aws.kms;

/**
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
 * The {@code AwsSessionConfig} class represents a configuration for an AWS
 * session,
 * containing the AWS access key ID and secret access key.
 * 
 */
public class AwsSessionConfig {
	private String awsAccessKeyId;
	private String awsSecretAccessKey;

	/**
	 * Constructs a new {@code AwsSessionConfig} instance with the specified AWS
	 * access key ID
	 * and secret access key.
	 *
	 * @param awsAccessKeyId     The AWS access key ID.
	 * @param awsSecretAccessKey The AWS secret access key.
	 */
	public AwsSessionConfig(String awsAccessKeyId, String awsSecretAccessKey) {
		this.awsAccessKeyId = awsAccessKeyId;
		this.awsSecretAccessKey = awsSecretAccessKey;
	}

	/**
	 * Returns the AWS access key ID.
	 *
	 * @return The AWS access key ID.
	 */
	public String getAwsAccessKeyId() {
		return awsAccessKeyId;
	}

	/**
	 * Sets the AWS access key ID.
	 *
	 * @param awsAccessKeyId The AWS access key ID.
	 */
	public void setAwsAccessKeyId(String awsAccessKeyId) {
		this.awsAccessKeyId = awsAccessKeyId;
	}

	/**
	 * Returns the AWS secret access key.
	 *
	 * @return The AWS secret access key.
	 */
	public String getAwsSecretAccessKey() {
		return awsSecretAccessKey;
	}

	/**
	 * Sets the AWS secret access key.
	 *
	 * @param awsSecretAccessKey The AWS secret access key.
	 */
	public void setAwsSecretAccessKey(String awsSecretAccessKey) {
		this.awsSecretAccessKey = awsSecretAccessKey;
	}
}