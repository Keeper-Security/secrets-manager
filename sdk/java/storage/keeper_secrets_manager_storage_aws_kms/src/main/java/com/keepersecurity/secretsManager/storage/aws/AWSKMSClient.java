package com.keepersecurity.secretsManager.storage.aws;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;

/**
 * AWSKMSClient class is used to encrypt and decrypt the message using the
 * specified KMS key.
 */
public class AWSKMSClient {

	final static Logger logger = LoggerFactory.getLogger(AWSKMSClient.class);

	private KmsClient kmsClient;

	/**
	 * Initialize AWSKMSClient with sessionConfig and region
	 * 
	 * @param sessionConfig The AWS session configuration for authentication.
	 * @param region        The AWS region where the KMS key is located.
	 * 
	 */
	public AWSKMSClient(AwsSessionConfig sessionConfig, Region region) {
		AwsBasicCredentials awsCreds = AwsBasicCredentials.create(sessionConfig.getAwsAccessKeyId(),
				sessionConfig.getAwsSecretAccessKey());
		kmsClient = KmsClient.builder().credentialsProvider(StaticCredentialsProvider.create(awsCreds))
				.region(region).build();
	}

	/**
	 * Initialize AWSKMSClient with profile and region
	 * 
	 * @param profile The AWS profile to use for authentication.
	 * @param region  The AWS region where the KMS key is located.
	 * 
	 */
	public AWSKMSClient(String profile, Region region) {
		ProfileCredentialsProvider awsCreds = ProfileCredentialsProvider.create(profile);
		kmsClient = KmsClient.builder()
				.region(region) // Specify the region
				.credentialsProvider(awsCreds) // Use default AWS credentials provider
				.build();
	}

	/**
	 * Encrypt the message using the specified KMS key.
	 * 
	 * @param message The message to encrypt.
	 * @param keyId   The KMS key ID to use for encryption.
	 * @return The encrypted message.
	 * @throws Exception Throws an exception if an error occurs during encryption.
	 */
	public byte[] encrypt(SdkBytes message, String keyId) throws Exception {
		if (Constants.SYMMETRIC_DEFAULT.equals(getKeySpecType(keyId))) {
			return encryptSymmetric(message, keyId);
		} else {
			return encryptAsymmetric(message, keyId);
		}
	}

	/**
	 * Decrypt the ciphertext using the specified KMS key.
	 * 
	 * @param ciphertext The ciphertext to decrypt.
	 * @param keyId      The KMS key ID to use for decryption.
	 * @return The decrypted message.
	 * @throws Exception Throws an exception if an error occurs during decryption.
	 */
	public SdkBytes decrypt(byte[] ciphertext, String keyId) throws Exception {
		if (Constants.SYMMETRIC_DEFAULT.equals(getKeySpecType(keyId))) {
			return decryptSymmetric(ciphertext, keyId);
		} else {
			return decryptAsymmetric(ciphertext, keyId);
		}
	}

	private String getKeySpecType(String keyId) {
		return kmsClient.describeKey(DescribeKeyRequest.builder().keyId(keyId).build()).keyMetadata()
				.keySpecAsString();
	}

	/**
	 * Check if the KMS key is a symmetric key.
	 * 
	 * @param keyId The KMS key ID to check.
	 * @return True if the key is a symmetric key, false otherwise.
	 */
	public boolean isSymmetricKey(String keyId) {
		if (Constants.SYMMETRIC_DEFAULT.equals(getKeySpecType(keyId))) {
			return true;
		}
		return false;
	}

	private byte[] encryptSymmetric(SdkBytes message, String keyId) throws Exception {
		logger.debug("Encrypt Using Symmetric Key");
		EncryptRequest encryptRequest = EncryptRequest.builder().keyId(keyId)
				.plaintext(message).build();
		EncryptResponse encryptResponse = kmsClient.encrypt(encryptRequest);
		return encryptResponse.ciphertextBlob().asByteArray();

	}

	private SdkBytes decryptSymmetric(byte[] ciphertext, String keyId) throws Exception {
		logger.debug("Decrypt Using Symmetric Key");
		DecryptRequest decryptRequest = DecryptRequest.builder().keyId(keyId)
				.ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
				.build();
		DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
		return decryptResponse.plaintext();
	}

	private byte[] encryptAsymmetric(SdkBytes message, String keyId) throws Exception {
		logger.debug("Encrypt Using Asymmetric Key");
		EncryptRequest encryptRequest = EncryptRequest.builder().keyId(keyId)
				.plaintext(message)
				.encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
				.build();
		EncryptResponse encryptResponse = kmsClient.encrypt(encryptRequest);
		return encryptResponse.ciphertextBlob().asByteArray();
	}

	private SdkBytes decryptAsymmetric(byte[] ciphertext, String keyId) throws Exception {
		logger.debug("Decrypt Using Asymmetric Key");
		DecryptRequest decryptRequest = DecryptRequest.builder().keyId(keyId)
				.ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
				.encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256)
				.build();
		DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
		return decryptResponse.plaintext();
	}
}