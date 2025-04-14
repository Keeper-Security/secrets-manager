package com.keepersecurity.secretsmanager.gcp;

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

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.kms.v1.AsymmetricDecryptResponse;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.cloud.kms.v1.PublicKey;
import com.google.protobuf.ByteString;
import com.google.cloud.kms.v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.cloud.kms.v1.DecryptRequest;
import com.google.cloud.kms.v1.EncryptRequest;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The {@code KMSUtils} class provides utility methods for encrypting and
 * decrypting data using Google Cloud Key Management Service (KMS).
 * It supports both asymmetric RSA encryption and symmetric encryption.
 */
public class KMSUtils {

	final static Logger logger = LoggerFactory.getLogger(KMSUtils.class);

	private KeyManagementServiceClient kmsClient;
	private GcpSessionConfig sessionConfig;
	private static final Map<String, String> rsaAlgorithmToSHA = new HashMap<>();

	static {
		// Initialize the mapping of algorithms to SHA types
		rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_2048_SHA256", "SHA-256");
		rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_3072_SHA256", "SHA-256");
		rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_4096_SHA256", "SHA-256");
		rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_4096_SHA512", "SHA-512");
		rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_2048_SHA1", "SHA-1");
		rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_3072_SHA1", "SHA-1");
		rsaAlgorithmToSHA.put("RSA_DECRYPT_OAEP_4096_SHA1", "SHA-1");
	}

	/**
	 * Constructs a new {@code KMSUtils} object with the specified session
	 * configuration.
	 *
	 * @param sessionConfig The GCP session configuration.
	 */
	public KMSUtils(GcpSessionConfig sessionConfig) {
		try {
			if (sessionConfig.getCredentialsPath().isEmpty()) {
				// Create the KMS client using Environment variable
				kmsClient = KeyManagementServiceClient.create();
			} else {
				// Load the credentials from the JSON key file
				GoogleCredentials credentials = GoogleCredentials
						.fromStream(new FileInputStream(sessionConfig.getCredentialsPath()));

				// Create the KeyManagementServiceSettings using the credentials
				KeyManagementServiceSettings kmsSettings = KeyManagementServiceSettings.newBuilder()
						.setCredentialsProvider(() -> credentials) // Provide credentials to the client
						.build();

				// Create the KeyManagementServiceClient with the specified settings
				kmsClient = KeyManagementServiceClient.create(kmsSettings);
			}
			this.sessionConfig = sessionConfig;

		} catch (Exception e) {
			logger.error("Exception: " + e.getMessage());
		}
	}

	/**
	 * Sets the key ID for the KMS client.
	 * 
	 * @param newKeyId The new key ID to set.
	 */
	public void setKeyId(String newKeyId) {
		this.sessionConfig.setKeyId(newKeyId);
	}

	/**
	 * Gets the key ID for the KMS client.
	 * 
	 * @return The key ID.
	 */
	public String getKeyId() {
		return this.sessionConfig.getKeyId();
	}

	/**
	 * Encrypt data using an asymmetric RSA public key
	 * 
	 * @param text Plaintext that needs to be encrypted using asymmetric key
	 * @return Encrypted text as a byte array
	 * @throws Exception Throws Exception, if any error occurs during encryption
	 */
	public byte[] encryptAsymmetricRsa(byte[] text) throws Exception {
		logger.debug("Encrypt Using Asymmetric Key");

		// Perform encryption and get the ciphertext
		CryptoKeyVersionName keyVersionName = getCryptoKeyVersionName();
		// Get the public key.
		PublicKey publicKey = kmsClient.getPublicKey(keyVersionName);

		// Convert the public PEM key to a DER key (see helper below).
		byte[] derKey = convertPemToDer(publicKey.getPem());
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);

		// Generate RSA public key from DER
		RSAPublicKey rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);

		CryptoKeyVersionAlgorithm algorithms = getCryptoKeyVersionAlgorithm();

		// Choose the appropriate OAEP padding algorithm based on the key size and hash
		String hashAlgorithm = getSHA(algorithms.name());
		// Initialize cipher with the correct transformation
		String transformation = "RSA/ECB/OAEPWith" + hashAlgorithm + "AndMGF1Padding";
		Cipher cipher = Cipher.getInstance(transformation);

		OAEPParameterSpec oaepParams = new OAEPParameterSpec(hashAlgorithm, "MGF1",
				new MGF1ParameterSpec(hashAlgorithm), PSource.PSpecified.DEFAULT);
		cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey, oaepParams);
		return cipher.doFinal(text);
	}

	/**
	 * Converts a base64-encoded PEM certificate like the one returned from Cloud
	 * KMS into a DER formatted certificate for use with the Java APIs.
	 * 
	 * @param pem The PEM certificate to convert.
	 * @return The DER formatted certificate as a byte array.
	 */
	private byte[] convertPemToDer(String pem) {
		BufferedReader bufferedReader = new BufferedReader(new StringReader(pem));
		String encoded = bufferedReader.lines()
				.filter(line -> !line.startsWith("-----BEGIN") && !line.startsWith("-----END"))
				.collect(Collectors.joining());
		return Base64.getDecoder().decode(encoded);
	}

	/**
	 * Decrypt data using an asymmetric RSA private key
	 * 
	 * @param ciphertext Encrypted text that needs to be decrypted using asymmetric
	 *                   key
	 * @return Decrypted text as a byte array
	 * @throws Exception Throws Exception, if any error occurs during decryption
	 */
	public byte[] decryptAsymmetricRsa(byte[] ciphertext) throws Exception {
		logger.debug("Decrypt Using Asymmetric Key");
		// Perform encryption and get the ciphertext
		CryptoKeyVersionName keyVersionName = getCryptoKeyVersionName();

		// Decrypt the ciphertext.
		AsymmetricDecryptResponse decryptedText = kmsClient.asymmetricDecrypt(keyVersionName,
				ByteString.copyFrom(ciphertext));

		// Convert the decrypted text back to String
		return decryptedText.getPlaintext().toByteArray();
	}

	/**
	 * Encrypt data using a symmetric key
	 * 
	 * @param plaintext Plaintext that needs to be encrypted using symmetric key
	 * @return Encrypted text as a byte array
	 * @throws Exception Throws Exception, if any error occurs during encryption
	 */
	public ByteString encryptSymmetric(String plaintext) throws Exception {
		logger.debug("Encrypt Using Symmetric Key");
		// Convert plaintext to ByteString
		ByteString plaintextByteString = ByteString.copyFrom(plaintext, StandardCharsets.UTF_8);

		// Encrypt the data
		EncryptRequest encryptRequest = EncryptRequest.newBuilder().setName(getFullName())
				.setPlaintext(plaintextByteString).build();
		ByteString ciphertext = kmsClient.encrypt(encryptRequest).getCiphertext();

		// Return encrypted text as a Base64 string
		return ciphertext;
	}

	/**
	 * Decrypt data using a symmetric key
	 * 
	 * @param ciphertext Encrypted text that needs to be decrypted using symmetric
	 *                   key
	 * @return Decrypted text as a string
	 * @throws Exception Throws Exception, if any error occurs during decryption
	 */
	public String decryptSymmetric(ByteString ciphertext) throws Exception {
		logger.debug("Decrypt Using Symmetric Key");
		// Decrypt the data
		DecryptRequest decryptRequest = DecryptRequest.newBuilder().setName(getFullName()).setCiphertext(ciphertext)
				.build();
		ByteString decryptedText = kmsClient.decrypt(decryptRequest).getPlaintext();

		// Convert the decrypted text back to String
		return decryptedText.toStringUtf8();
	}

	private String getFullName() {
		return String.format("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", sessionConfig.getProjectId(),
				sessionConfig.getLocation(), sessionConfig.getKeyRing(), sessionConfig.getKeyId());
	}

	/**
	 * Checks if the key is a symmetric key.
	 * 
	 * @return true if the key is symmetric, false otherwise.
	 */
	public boolean isSymmetricKey() {
		// Fetch the key version (use the primary version of the key)
		CryptoKeyVersionAlgorithm algorithms = getCryptoKeyVersionAlgorithm();
		logger.debug("Encryption Algorithm :::" + algorithms.name());
		if (algorithms.name().contains("SYMMETRIC"))
			return true;

		return false;

	}

	/**
	 * Checks if the key is a raw symmetric key.
	 * 
	 * @return true if the key is a raw symmetric key, false otherwise.
	 */
	public boolean isKeyRAWSymmteric() {
		CryptoKeyVersionAlgorithm algorithms = getCryptoKeyVersionAlgorithm();
		logger.debug("Encryption Algorithm :::" + algorithms.name());
		if (algorithms.name().contains("AES_")) {
			return true;
		}
		return false;
	}

	private String getSHA(String rsaAlgorithm) throws IllegalArgumentException {
		String shaAlgorithm = rsaAlgorithmToSHA.get(rsaAlgorithm);
		if (shaAlgorithm == null) {
			throw new IllegalArgumentException("Unsupported RSA algorithm: " + rsaAlgorithm);
		}
		return shaAlgorithm;
	}

	private CryptoKeyVersionAlgorithm getCryptoKeyVersionAlgorithm() {
		CryptoKeyVersionName keyVersionName = getCryptoKeyVersionName();
		CryptoKeyVersion cryptoKeyVersion = kmsClient.getCryptoKeyVersion(keyVersionName);
		CryptoKeyVersionAlgorithm algorithms = cryptoKeyVersion.getAlgorithm();
		return algorithms;
	}

	private CryptoKeyVersionName getCryptoKeyVersionName() {
		CryptoKeyVersionName keyVersionName = CryptoKeyVersionName.of(sessionConfig.getProjectId(),
				sessionConfig.getLocation(), sessionConfig.getKeyRing(), sessionConfig.getKeyId(),
				sessionConfig.getKeyVersion());
		return keyVersionName;
	}

	/**
	 * Encrypts data using a raw symmetric key.
	 * 
	 * @param sessionConfig GCPSession Config
	 * @param message       The message to encrypt.
	 * @param token         The authentication token
	 * @return The encrypted response containing ciphertext and initialization
	 *         vector.
	 * @throws Exception Throws Exception, If an error occurs during encryption.
	 */
	public EncryptResponse encryptRawSymmetric(GcpSessionConfig sessionConfig, byte[] message, String token)
			throws Exception {
		logger.debug("Encrypt Using Raw Symmetric Key");
		String encodeAAD = Base64.getEncoder().encodeToString(Constants.additionalAuthenticatedData);
		String encodedMessage = Base64.getEncoder().encodeToString(message);
		String apiUrl = String.format(
				"https://cloudkms.googleapis.com/v1/projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s:rawEncrypt",
				sessionConfig.getProjectId(), sessionConfig.getLocation(), sessionConfig.getKeyRing(),
				sessionConfig.getKeyId(), sessionConfig.getKeyVersion());

		String payload = String.format(
				"{\"plaintext\": \"%s\", \"additionalAuthenticatedData\": \"%s\"}",
				encodedMessage, encodeAAD);

		URL url = URI.create(apiUrl).toURL();
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Authorization", "Bearer " + token);
		connection.setRequestProperty("Content-Type", "application/json");
		connection.setDoOutput(true);

		try (OutputStream os = connection.getOutputStream()) {
			byte[] input = payload.getBytes(StandardCharsets.UTF_8);
			os.write(input, 0, input.length);
		}

		int responseCode = connection.getResponseCode();
		if (responseCode == HttpURLConnection.HTTP_OK) {
			logger.debug("Raw encryption successful");
			try (var reader = new java.io.BufferedReader(
					new java.io.InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
				StringBuilder response = new StringBuilder();
				String line;
				while ((line = reader.readLine()) != null) {
					response.append(line.trim());
				}
				String responseJson = response.toString();
				logger.debug("Response JSON: " + responseJson);
				JsonObject jsonObject = JsonParser.parseString(responseJson).getAsJsonObject();
				String ciphertext = jsonObject.get("ciphertext").getAsString();
				String initializeVector = jsonObject.get("initializationVector").getAsString();
				return new EncryptResponse(ciphertext, initializeVector);
			}
		} else {
			logger.error("Raw encryption failed with HTTP code: " + responseCode);
			try (var reader = new java.io.BufferedReader(
					new java.io.InputStreamReader(connection.getErrorStream(), StandardCharsets.UTF_8))) {
				StringBuilder errorResponse = new StringBuilder();
				String line;
				while ((line = reader.readLine()) != null) {
					errorResponse.append(line.trim());
				}
				logger.error("Error Response: " + errorResponse);
			}
		}

		throw new IOException("Failed to perform raw encryption. HTTP code: " + responseCode);
	}

	/**
	 * Decrypts data using a raw symmetric key.
	 * 
	 * @param sessionConfig        GCP Session Config
	 * @param ciphertext           The ciphertext to decrypt.
	 * @param initializationVector The initialization vector used during encryption.
	 * @param token                The authentication token.
	 * @return The decrypted plaintext as a byte array.
	 * @throws Exception Throws Exception, If an error occurs during decryption.
	 */
	public byte[] decryptRawSymmetric(GcpSessionConfig sessionConfig, byte[] ciphertext, byte[] initializationVector,
			String token) throws Exception {
		logger.debug("Decrypt Using Raw Symmetric Key");
		byte[] decodedCiphertext = Base64.getDecoder().decode(ciphertext);
		byte[] decodedInitializationVector = Base64.getDecoder().decode(initializationVector);
		String encodeAAD = Base64.getEncoder().encodeToString(Constants.additionalAuthenticatedData);
		String encodedCiphertext = Base64.getEncoder().encodeToString(decodedCiphertext);
		String initializationVectorBase64 = Base64.getEncoder().encodeToString(decodedInitializationVector);
		String apiUrl = String.format(
				"https://cloudkms.googleapis.com/v1/projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s:rawDecrypt",
				sessionConfig.getProjectId(), sessionConfig.getLocation(), sessionConfig.getKeyRing(),
				sessionConfig.getKeyId(), sessionConfig.getKeyVersion());

		String payload = String.format(
				"{\"ciphertext\": \"%s\", \"additionalAuthenticatedData\": \"%s\", \"initializationVector\": \"%s\"}",
				encodedCiphertext, encodeAAD, initializationVectorBase64);

		URL url = URI.create(apiUrl).toURL();
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Authorization", "Bearer " + token);
		connection.setRequestProperty("Content-Type", "application/json");
		connection.setDoOutput(true);

		try (OutputStream os = connection.getOutputStream()) {
			byte[] input = payload.getBytes(StandardCharsets.UTF_8);
			os.write(input, 0, input.length);
		}

		int responseCode = connection.getResponseCode();
		if (responseCode == HttpURLConnection.HTTP_OK) {
			logger.debug("Raw decryption successful");
			try (var reader = new java.io.BufferedReader(
					new java.io.InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
				StringBuilder response = new StringBuilder();
				String line;
				while ((line = reader.readLine()) != null) {
					response.append(line.trim());
				}

				String responseJson = response.toString();
				logger.debug("Response JSON: " + responseJson);
				JsonObject jsonObject = JsonParser.parseString(responseJson).getAsJsonObject();
				String plaintext = jsonObject.get("plaintext").getAsString();
				return Base64.getDecoder().decode(plaintext);
			}
		} else {
			logger.error("Raw decryption failed with HTTP code: " + responseCode);
			try (var reader = new java.io.BufferedReader(
					new java.io.InputStreamReader(connection.getErrorStream(), StandardCharsets.UTF_8))) {
				StringBuilder errorResponse = new StringBuilder();
				String line;
				while ((line = reader.readLine()) != null) {
					errorResponse.append(line.trim());
				}
				logger.error("Error Response: " + errorResponse);
			}
		}

		throw new IOException("Failed to perform raw decryption. HTTP code: " + responseCode);
	}
}
