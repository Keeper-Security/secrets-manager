package com.keepersecurity.secretsManager.storage.oracle;

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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.keepersecurity.secretsManager.core.KeyValueStorage;

/**
 * The {@code OracleKeyValueStorage} class is an implementation of the
 * {@code KeyValueStorage} interface that provides methods for storing and
 * retrieving key-value pairs using the Oracle Key vault(OCI).
 * 
 */
public class OracleKeyValueStorage implements KeyValueStorage {
	final static Logger logger = LoggerFactory.getLogger(OracleKeyValueStorage.class);

	private String defaultConfigFileLocation = "client-config.json";
	private String lastSavedConfigHash, updateConfigHash;
	private String configFileLocation;
	private String keyId;
	private String keyVersionId;
	private Map<String, Object> configMap;

	private OracleKeyVaultConnector ociClient;

	/**
	 * Constructor used to initialize Oracle KeyValueStorage
	 * 
	 * @param configFileLocation Configuration file location
	 * @param profile            The Oracle secret profile [DEFAULT] used for
	 *                           authentication
	 * @param sessionConfig      Session Configuration instance
	 * @throws Exception Throws Exception
	 */
	public OracleKeyValueStorage(String configFileLocation, String profile, OracleSessionConfig sessionConfig)
			throws Exception {
		this.configFileLocation = configFileLocation != null ? configFileLocation
				: System.getenv("KSM_CONFIG_FILE") != null ? System.getenv("KSM_CONFIG_FILE")
						: this.defaultConfigFileLocation;
		this.keyId = sessionConfig.getKeyId();
		this.keyVersionId = sessionConfig.getKeyVersionId();
		this.configMap = new HashMap<String, Object>();
		ociClient = new OracleKeyVaultConnector(sessionConfig, profile);
		logger.info("Oracle KMS Client initiated.");
		loadConfig();
	}

	/**
	 * Creates and returns an instance of {@code OracleKeyValueStorage}.
	 * 
	 * @param keyId              The OCI key id used for encryption/decryption
	 * @param keyVersion         The OCI key version used for encryption/decryption
	 * @param profile            The OCI profile used for authentication
	 * @param configFileLocation The file path to the KSM configuration file.
	 * @param sessionConfig      The Oracle session configuration for
	 *                           authentication.
	 * @return An instance of {@code OracleKeyValueStorage}.
	 * @throws Exception If an error occurs during initialization or configuration
	 *                   loading.
	 */
	public static OracleKeyValueStorage getInternalStorage(String keyId, String keyVersion, String configFileLocation,
			String profile,
			OracleSessionConfig sessionConfig) throws Exception {
		OracleKeyValueStorage storage = new OracleKeyValueStorage(configFileLocation, profile, sessionConfig);
		return storage;
	}

	/**
	 * Change key method used to encrypt config with new key
	 * 
	 * @param newKeyId      New Key ID
	 * @param newKeyVersion New Key Version
	 * @return true if key change is successful, false otherwise.
	 */
	public boolean changeKey(String newKeyId, String newKeyVersion) {
		logger.info("Change Key initiated");
		String configJson = "";
		String oldKey = this.keyId;
		String oldKeyVersion = this.keyVersionId;
		OracleKeyVaultConnector oldOciClient = this.ociClient;
		try {
			this.ociClient.sessionConfig.setKeyId(newKeyId);
			this.ociClient.sessionConfig.setKeyVersionId(newKeyVersion);
			save(configJson, configMap);
			logger.info("Encrypted using new KeyId");
			return true;
		} catch (Exception e) {
			this.keyId = oldKey;
			this.keyVersionId = oldKeyVersion;
			this.ociClient = oldOciClient;
			logger.error("Exception raised while changing key: " + e.getMessage());
		}
		return false;
	}

	/**
	 * Load the Configuration from file
	 * 
	 * @throws Exception
	 */
	private void loadConfig() throws Exception {
		File file = new File(configFileLocation);
		// File file = new File(configFileLocation);
		if (file.exists() && file.length() == 0) {
			logger.info("File is empty");
			return;
		}

		if (!JsonUtil.isValidJsonFile(configFileLocation)) {
			logger.debug("KSM config file is already encrypted.");
			String decryptedContent = decryptBuffer(readEncryptedJsonFile());
			lastSavedConfigHash = calculateMd5(decryptedContent);
			configMap = JsonUtil.convertToMap(decryptedContent);
		} else {
			logger.debug("KSM Config file is plain json.");
			String configJson = new String(Files.readAllBytes(Paths.get(configFileLocation)), java.nio.charset.StandardCharsets.UTF_8);
			lastSavedConfigHash = calculateMd5(configJson);
			configMap = JsonUtil.convertToMap(configJson);
			saveConfig(configMap);
		}
	}

	private void saveConfig(Map<String, Object> updatedConfig) {
		try {
			if (JsonUtil.isValidJsonFile(configFileLocation)) {
				Path path = Paths.get(configFileLocation);
				save(new String(Files.readAllBytes(path), java.nio.charset.StandardCharsets.UTF_8), updatedConfig);
			} else{
				String decryptedContent = decryptBuffer(readEncryptedJsonFile());
				save(decryptedContent, updatedConfig);
			}
		} catch (Exception e) {
			logger.error("Exception:" + e.getMessage());
		}
	}

	private void save(String configJson, Map<String, Object> updatedConfig) {
		if (updatedConfig != null && updatedConfig.size() > 0) {
			try {
				lastSavedConfigHash = calculateMd5(configJson);
				String updatedConfigJson = JsonUtil.convertToString(updatedConfig);
				updateConfigHash = calculateMd5(updatedConfigJson);
				if (updateConfigHash != lastSavedConfigHash) {
					lastSavedConfigHash = updateConfigHash;
					configJson = updatedConfigJson;
					configMap = JsonUtil.convertToMap(configJson);
				}
				byte[] encryptedData = encryptBuffer(configJson);
				Files.write(Paths.get(configFileLocation), encryptedData);
				logger.info("KSM config saved fo file success.");
			} catch (Exception e) {
				logger.error("Exception:" + e.getMessage());
			}
		}
	}

	private byte[] readEncryptedJsonFile() throws Exception {
		Path path = Paths.get(configFileLocation);
		if (!Files.exists(path)) {
			createConfigFileIfMissing();
		}
		return Files.readAllBytes(path);
	}

	/**
	 * 
	 * @param stream
	 * @param data
	 * @throws IOException
	 */
	private void writeLengthPrefixed(ByteArrayOutputStream stream, byte[] data) throws IOException {
		stream.write((data.length >> 8) & 0xFF);
		stream.write(data.length & 0xFF);
		stream.write(data);
	}

	/**
	 * Generate GCM Cipher
	 * 
	 * @param mode
	 * @param iv
	 * @param key
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws InvalidKeySpecException
	 */
	private Cipher getGCMCipher(int mode, byte[] iv, byte[] key) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {

		Cipher cipher = Cipher.getInstance(Constants.AES_GCM);
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(Constants.GCM_TAG_LENGTH, iv);
		SecretKeySpec keySpec = new SecretKeySpec(key, Constants.AES);
		cipher.init(mode, keySpec, gcmParameterSpec);
		return cipher;
	}

	private byte[] encryptBuffer(String message) throws Exception {
		if (ociClient.isSymmetricKey(keyId)) {
			byte[] encrypted = ociClient.encryptAES(message.getBytes());
			ByteArrayOutputStream blob = new ByteArrayOutputStream();
			writeLengthPrefixed(blob, encrypted);
			return blob.toByteArray();
		} else {
			byte[] nance = new byte[Constants.BLOCK_SIZE];
			byte[] key = new byte[Constants.KEY_SIZE];
			Cipher cipher = getGCMCipher(Cipher.ENCRYPT_MODE, key, nance);
			byte[] ciphertext = cipher.doFinal(message.getBytes());

			byte[] tag = cipher.getIV();
			byte[] encryptedKey = ociClient.encryptRSA(key);

			ByteArrayOutputStream blob = new ByteArrayOutputStream();
			blob.write(Constants.BLOB_HEADER);
			writeLengthPrefixed(blob, encryptedKey);
			writeLengthPrefixed(blob, nance);
			writeLengthPrefixed(blob, tag);
			writeLengthPrefixed(blob, ciphertext);
			return blob.toByteArray();
		}
	}

	/**
	 * 
	 * @param encryptedData
	 * @return
	 * @throws Exception
	 */
	private String decryptBuffer(byte[] encryptedData) throws Exception {
		if (ociClient.isSymmetricKey(keyId)) {
			ByteArrayInputStream blobInputStream = new ByteArrayInputStream(encryptedData);
			byte[] encrypted = readLengthPrefixed(blobInputStream);
			byte[] decryptedMessage = ociClient.decryptAES(encrypted);
			String decryptedString = new String(decryptedMessage, StandardCharsets.UTF_8).trim();
			if (!JsonUtil.isValidJson(decryptedString)) {
				throw new IllegalArgumentException("Decrypted content is not valid JSON.");
			}
			return new String(decryptedMessage, StandardCharsets.UTF_8);

		} else {
			ByteArrayInputStream blobInputStream = new ByteArrayInputStream(encryptedData);

			byte[] header = new byte[Constants.BLOB_HEADER.length];
			blobInputStream.read(header);
			if (!MessageDigest.isEqual(header, Constants.BLOB_HEADER)) {
				throw new IllegalArgumentException("Invalid blob header");
			}
			byte[] encryptedKey = readLengthPrefixed(blobInputStream);
			byte[] nonce = readLengthPrefixed(blobInputStream);
			byte[] tag = readLengthPrefixed(blobInputStream);
			byte[] ciphertext = readLengthPrefixed(blobInputStream);

			// Decrypt the AES key using RSA (unwrap the key)
			byte[] key = ociClient.decryptRSA(encryptedKey);
			Cipher cipher = getGCMCipher(Cipher.DECRYPT_MODE, key, nonce);

			byte[] decryptedMessage = cipher.doFinal(ciphertext);
			return new String(decryptedMessage, StandardCharsets.UTF_8);
		}
	}

	/**
	 * Decrypt the encrypted config.
	 * 
	 * @param autosave Set to {@code true} to save the KSM configuration JSON file
	 *                 as plaintext, and {@code false} to retrieve only the
	 *                 plaintext of the KSM configuration.
	 * @return The decrypted configuration as a String.
	 * @throws Exception If an error occurs during the decryption process.
	 */
	public String decryptConfig(boolean autosave) throws Exception {
		String decryptedContent = null;
		if (!JsonUtil.isValidJsonFile(configFileLocation)) {
			decryptedContent = decryptBuffer(readEncryptedJsonFile());
			if (autosave) {
				Path path = Paths.get(configFileLocation);
				if (Files.exists(path)) {
					Files.write(path, decryptedContent.getBytes(StandardCharsets.UTF_8));
					logger.info("Decrypted KSM config saved into file success.");
				}
			}
			return decryptedContent;
		} else {
			logger.info("KSM config is plain json only.");
			return null;
		}
	}

	private byte[] readLengthPrefixed(InputStream stream) throws IOException {
		int length = (stream.read() << 8) | stream.read();
		byte[] data = new byte[length];
		stream.read(data);
		return data;
	}

	/**
	 * 
	 * @throws Exception
	 */
	private void createConfigFileIfMissing() throws Exception {
		Path path = Paths.get(configFileLocation);
		if (!Files.exists(path)) {
			Files.write(path, encryptBuffer("{}"));
		}
	}

	private String calculateMd5(String input) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(digest);
	}

	/**
	 * Convert base64 string to byte array
	 * 
	 * @param base64String The base64 encoded string to be converted
	 * @return Byte array representation of the base64 string
	 */
	public byte[] base64ToBytes(String base64String) {
		if (base64String == null || base64String.isEmpty()) {
			return null; // Or you can throw an IllegalArgumentException based on your preference
		}
		return Base64.getDecoder().decode(base64String);
	}

	private String bytesToBase64(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	@Override
	public void delete(String key) {
		if (configMap.isEmpty()) {
			try {
				loadConfig();
			} catch (Exception e) {
				logger.error("Failed to load config file.", e);
			}
		}
		configMap.remove(key);
		saveConfig(configMap);
	}

	@Override
	public byte[] getBytes(String key) {
		if (configMap.get(key) == null)
			return null;
		return base64ToBytes(configMap.get(key).toString());
	}

	@Override
	public String getString(String key) {
		if (configMap.isEmpty()) {
			try {
				loadConfig();
			} catch (Exception e) {
				logger.error("Failed to load config file.", e);
			}
		}
		if (configMap.get(key) == null)
			return null;
		return configMap.get(key).toString();
	}

	@Override
	public void saveBytes(String key, byte[] value) {
		if (configMap.isEmpty()) {
			try {
				loadConfig();
			} catch (Exception e) {
				logger.error("Failed to load config file.", e);
			}
		}
		configMap.put(key, bytesToBase64(value));
		saveConfig(configMap);
	}

	@Override
	public void saveString(String key, String value) {
		if (configMap.isEmpty()) {
			try {
				loadConfig();
			} catch (Exception e) {
				logger.error("Failed to load config file.", e);
			}
		}
		configMap.put(key, value);
		saveConfig(configMap);
	}

	@Override
	public String toString() {
		if (configMap.isEmpty()) {
			try {
				loadConfig();
			} catch (Exception e) {
				logger.error("Failed to load config file.", e);
			}
		}
		try {
			return JsonUtil.convertToString(configMap);
		} catch (JsonProcessingException e) {
			logger.error("Exception: " + e.getMessage());
		}
		return null;
	}
}
