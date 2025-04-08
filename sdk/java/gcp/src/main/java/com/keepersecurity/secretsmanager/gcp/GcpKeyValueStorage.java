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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.protobuf.ByteString;
import com.keepersecurity.secretsManager.core.KeyValueStorage;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@code GcpKeyValueStorage} class provides a {@code KeyValueStorage}
 * interface that provides methods for storing and retrieving key-value pairs
 * using the GCP Key Management Vault.
 */
public class GcpKeyValueStorage implements KeyValueStorage {

	final static Logger logger = LoggerFactory.getLogger(GcpKeyValueStorage.class);
	private String defaultConfigFileLocation = "client-config.json";
	private String lastSavedConfigHash, updateConfigHash;
	private String configFileLocation;
	private Map<String, Object> configMap;

	private KMSUtils kmsClient;

	/**
	 * Initialize the GCP Key Management Service Client with the given config and
	 * session config object
	 * 
	 * @param configFileLocation KSM Config file location
	 * @param sessionConfig      GCP Session Config object
	 * @throws Exception Throw Execption, if any error occurs while initializing the
	 *                   client
	 */
	public GcpKeyValueStorage(String configFileLocation, GcpSessionConfig sessionConfig) throws Exception {
		this.configFileLocation = configFileLocation != null ? configFileLocation
				: System.getenv("KSM_CONFIG_FILE") != null ? System.getenv("KSM_CONFIG_FILE")
						: this.defaultConfigFileLocation;
		kmsClient = new KMSUtils(sessionConfig);
		logger.info("GCP Key Management Service Client initiated.");
		loadConfig();
	}

	/**
	 * Get the internal storage object with the given config file location and
	 * session config.
	 * 
	 * @param configFileLocation KSM Config file location
	 * @param sessionConfig      GCP Session Config object
	 * @return GcpKeyValueStorage object
	 * @throws Exception Throw Execption, if any error occurs while initializing the
	 *                   {@code GCPKeyValueStorage}.
	 */
	public static GcpKeyValueStorage getInternalStorage(String configFileLocation, GcpSessionConfig sessionConfig)
			throws Exception {
		GcpKeyValueStorage storage = new GcpKeyValueStorage(configFileLocation, sessionConfig);
		return storage;
	}

	/**
	 * Change key method used to re-encrypt the config with new Key
	 * 
	 * @param newKeyId New Key ID for re-encryption
	 * @return {@code true} if the key change was successful, {@code false}
	 *         otherwise.
	 */
	public boolean changeKey(String newKeyId) {
		logger.info("Change Key initiated");
		String oldKey = kmsClient.getKeyId();
		String configJson = "";
		Map<String, Object> oldconfigMap = this.configMap;
		try {
			kmsClient.setKeyId(newKeyId);
			save(configJson, configMap);
			logger.info("Encrypted using newKeyId success.");
			return true;
		} catch (Exception e) {
			kmsClient.setKeyId(oldKey);
			logger.error("Exception: " + e.getMessage());
		}
		return false;
	}

	/**
	 * Load the config from KSM json file
	 * 
	 * @throws Exception
	 */
	private void loadConfig() throws Exception {
		File file = new File(configFileLocation);
		if (file.exists() && file.length() == 0) {
			logger.info("File is empty");
			return;
		}
		if (!JsonUtil.isValidJsonFile(configFileLocation)) {
			logger.debug("loadConfig::File is encryped.");
			String decryptedContent = decryptBuffer(readEncryptedJsonFile());
			lastSavedConfigHash = calculateMd5(decryptedContent);
			configMap = JsonUtil.convertToMap(decryptedContent);
			logger.debug("loadConfig::configMap loaded from file.");
		} else {
			logger.debug("loadConfig::File is plain json.");
			String configJson = Files.readString(Paths.get(configFileLocation));
			lastSavedConfigHash = calculateMd5(configJson);
			configMap = JsonUtil.convertToMap(configJson);
			saveConfig(configMap);
		}
		logger.info("KSM config saved into file success.");
	}

	private void saveConfig(Map<String, Object> updatedConfig) {
		try {
			if (JsonUtil.isValidJsonFile(configFileLocation)) {
				Path path = Paths.get(configFileLocation);
				save(Files.readString(path), updatedConfig);
			} else {
				String decryptedContent = decryptBuffer(readEncryptedJsonFile());
				save(decryptedContent, updatedConfig);
			}
		} catch (Exception e) {
			logger.error("Exception: " + e.getMessage());
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
				logger.debug("Encrypted json content.");
				Files.write(Paths.get(configFileLocation), encryptedData);
			} catch (Exception e) {
				logger.error("Exception: " + e.getMessage());
			}
		}
	}

	/**
	 * Decrypt the encrypted config, autosave=true/false
	 * 
	 * @param autosave Set to {@code true} to save the ksm configuration json file
	 *                 as plaintext, and {@code false} to retrieve only the
	 *                 plaintext of the KSM configuration.
	 * @return The decrypted configuration as a String.
	 * @throws Exception Throws Exception, if any error occurs during decryption.
	 */
	public String decryptConfig(boolean autosave) throws Exception {
		String decryptedContent = null;
		if (!JsonUtil.isValidJsonFile(configFileLocation)) {
			decryptedContent = decryptBuffer(readEncryptedJsonFile());
			if (autosave) {
				Path path = Paths.get(configFileLocation);
				if (Files.exists(path))
					Files.write(path, decryptedContent.getBytes(StandardCharsets.UTF_8));
				logger.info("Decrypted KSM config saved into file success.");
			}
			return decryptedContent;
		} else {
			logger.info("KSM config is plain json only.");
			return null;
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
		if (kmsClient.isSymmetricKey()) {
			byte[] encrypted = kmsClient.encryptSymmetric(message).toByteArray();
			ByteArrayOutputStream blob = new ByteArrayOutputStream();
			writeLengthPrefixed(blob, encrypted);
			return blob.toByteArray();
		} else {
			byte[] nonce = new byte[Constants.BLOCK_SIZE];
			byte[] key = new byte[Constants.KEY_SIZE];
			Cipher cipher = getGCMCipher(Cipher.ENCRYPT_MODE, key, nonce);
			byte[] ciphertext = cipher.doFinal(message.getBytes());

			byte[] tag = cipher.getIV();
			byte[] encryptedKey = kmsClient.encryptAsymmetricRsa(key);

			ByteArrayOutputStream blob = new ByteArrayOutputStream();
			blob.write(Constants.BLOB_HEADER);
			writeLengthPrefixed(blob, encryptedKey);
			writeLengthPrefixed(blob, nonce);
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
		if (kmsClient.isSymmetricKey()) {
			ByteArrayInputStream blobInputStream = new ByteArrayInputStream(encryptedData);
			byte[] encrypted = readLengthPrefixed(blobInputStream);
			return kmsClient.decryptSymmetric(ByteString.copyFrom(encrypted));

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
			byte[] key = kmsClient.decryptAsymmetricRsa(encryptedKey);

			Cipher cipher = getGCMCipher(Cipher.DECRYPT_MODE, key, nonce);

			byte[] decryptedMessage = cipher.doFinal(ciphertext);
			return new String(decryptedMessage, StandardCharsets.UTF_8);
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

	private byte[] base64ToBytes(String base64String) {
		if (base64String == null || base64String.isEmpty()) {
			return null;
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