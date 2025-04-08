package com.keepersecurity.secretmanager.azurekv;

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

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.UnwrapResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.keepersecurity.secretsManager.core.KeyValueStorage;
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
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * The {@code AzureKeyValueStorage} class provides an implementation of the
 * {@code KeyValueStorage} interface that provides methods for storing and
 * retrieving key-value pairs using the Azure Key Vault (AKV).
 */
public class AzureKeyValueStorage implements KeyValueStorage {

	final static Logger logger = LoggerFactory.getLogger(AzureKeyValueStorage.class);

	private String defaultConfigFileLocation = "client-config.json";
	/**
	 * The {@code KeyClient} instance used to interact with the Azure Key Vault.
	 */
	public KeyClient keyClient;
	/**
	 * The KeyId of the master key used for encryption and decryption.
	 */
	public String keyId;
	private CryptographyClient cryptoClient;
	private TokenCredential tokencredential;
	private String lastSavedConfigHash, updateConfigHash;
	private String configFileLocation;
	Map<String, Object> configMap;

	/**
	 * Constructor for {@code AzureKeyValueStorage} class.
	 * 
	 * @param keyId              URI of the master key - if missing read from env
	 *                           KSM_AZ_KEY_ID, keyId URI may also include version
	 *                           in case key has auto rotate enabled
	 *                           The master key needs WrapKey, UnwrapKey privileges
	 * @param configFileLocation provides custom config file location - if missing
	 *                           read from env KSM_CONFIG_FILE
	 * @param azSessionConfig    optional az session config - if missing use default
	 *                           env variables
	 * @throws Exception Throws Exception, when the AzureKeyValueStorage cannot be
	 *                   created
	 *                   For more details
	 *                   https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential
	 */
	public AzureKeyValueStorage(String keyId, String configFileLocation, AzureSessionConfig azSessionConfig)
			throws Exception {
		this.configFileLocation = configFileLocation != null ? configFileLocation
				: System.getenv(Constants.KSM_CONFIG_FILE) != null ? System.getenv(Constants.KSM_CONFIG_FILE)
						: this.defaultConfigFileLocation;
		this.keyId = keyId != null ? keyId : System.getenv(Constants.KSM_AZ_KEY_ID);
		this.configMap = new HashMap<>();
		tokencredential = getSecretCredential(azSessionConfig);
		cryptoClient = getCryptoClient(this.keyId);
		logger.info("Azure Crypto Client initiated.");
		loadConfig();
	}

	private CryptographyClient getCryptoClient(String keyId) {
		return new CryptographyClientBuilder().credential(tokencredential).keyIdentifier(keyId).buildClient();
	}

	/**
	 * Create and return a new instance of {@code AzureKeyValueStorage}
	 * 
	 * @param keyId              URI of the master key - if missing read from env
	 *                           KSM_AZ_KEY_ID, keyId URI may also include version
	 *                           in case key has auto rotate enabled
	 * @param configFileLocation provides custom config file location - if missing
	 *                           read from env KSM_CONFIG_FILE
	 * @param azSessionConfig    optional az session config - if missing use default
	 *                           env variables
	 * @return A new instance of {@code AzureKeyValueStorage}
	 * @throws Exception Throws Exception, when the AzureKeyValueStorage cannot be
	 *                   created
	 */
	public static AzureKeyValueStorage getInternalStorage(String keyId, String configFileLocation,
			AzureSessionConfig azSessionConfig) throws Exception {
		AzureKeyValueStorage storage = new AzureKeyValueStorage(keyId, configFileLocation, azSessionConfig);
		return storage;
	}

	/**
	 * Creates and returns a {@link TokenCredential} instance using the provided
	 * Azure session configuration.
	 *
	 * @param azSessionConfig The Azure session configuration containing the client
	 *                        ID, client secret,
	 *                        and tenant ID required to authenticate with Azure.
	 * @return A {@link TokenCredential} instance that can be used to authenticate
	 *         with Azure services.
	 */
	private static TokenCredential getSecretCredential(AzureSessionConfig azSessionConfig) {
		return new ClientSecretCredentialBuilder().clientId(azSessionConfig.getClientId())
				.clientSecret(azSessionConfig.getClientSecret()).tenantId(azSessionConfig.getTenantId()).build();
	}

	/**
	 * Change key method used to re-encrypt the config with new Key
	 * 
	 * @param newKeyId new key id to be used for re-encrypting the config
	 * @return true if the key was changed successfully, false otherwise
	 */
	public boolean changeKey(String newKeyId) {
		logger.info("Change Key initiated");
		String configJson = "";
		String oldKey = this.keyId;
		Map<String, Object> oldconfigMap = this.configMap;
		CryptographyClient oldCryptoClient = this.cryptoClient;

		try {
			this.keyId = newKeyId;
			this.cryptoClient = getCryptoClient(newKeyId);
			save(configJson, configMap);
			logger.debug("Encrypted using new KeyId");
			return true;
		} catch (Exception e) {
			this.keyId = oldKey;
			this.cryptoClient = oldCryptoClient;
			logger.error("Exception: " + e.getMessage());
		}
		return false;
	}

	/**
	 * Load the configuration for encrypt/decrypt
	 * 
	 * @throws Exception
	 */
	private void loadConfig() throws Exception {
		File file = new File(configFileLocation);
		if (file.exists() && file.length() == 0) {
			logger.info("File is empty");
			return;
		}
		if (!JsonUtils.isValidJsonFile(configFileLocation)) {
			String decryptedContent = decryptBuffer(readEncryptedJsonFile());
			lastSavedConfigHash = calculateMd5(decryptedContent);
			configMap = JsonUtils.convertToMap(decryptedContent);
		} else {
			String configJson = Files.readString(Paths.get(configFileLocation));
			lastSavedConfigHash = calculateMd5(configJson);
			configMap = JsonUtils.convertToMap(configJson);
			saveConfig(configMap);
		}
	}

	/**
	 * Save configuration encrypted configuration
	 * 
	 * @param updatedConfig
	 */
	private void saveConfig(Map<String, Object> updatedConfig) {
		try {
			if (JsonUtils.isValidJsonFile(configFileLocation)) {
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
				String updatedConfigJson = JsonUtils.convertToString(updatedConfig);
				updateConfigHash = calculateMd5(updatedConfigJson);
				if (updateConfigHash != lastSavedConfigHash) {
					lastSavedConfigHash = updateConfigHash;
					configJson = updatedConfigJson;
					configMap = JsonUtils.convertToMap(configJson);
				}
				byte[] encryptedData = encryptBuffer(configJson);
				Files.write(Paths.get(configFileLocation), encryptedData);
				logger.debug("KSM config saved into file success.");
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
	 * @throws Exception If an error occurs during the decryption process.
	 */
	public String decryptConfig(boolean autosave) throws Exception {
		String decryptedContent = null;
		if (!JsonUtils.isValidJsonFile(configFileLocation)) {
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
			logger.debug("KSM config is plain json only.");
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
	 * Write the encrypted configuration with key into file
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
	private Cipher getGCMCipher(int mode, byte[] iv, byte[] key)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {

		Cipher cipher = Cipher.getInstance(Constants.AES_GCM);
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(Constants.GCM_TAG_LENGTH, iv);
		SecretKeySpec keySpec = new SecretKeySpec(key, Constants.AES);
		cipher.init(mode, keySpec, gcmParameterSpec);
		return cipher;
	}

	/**
	 * Azure keyvault supports symmetric keys on Managed HSM only
	 * generate and wrap temp AES (GCM) 256-bit keys
	 * 
	 * @param message
	 * @return
	 * @throws Exception
	 */
	private byte[] encryptBuffer(String message) throws Exception {

		byte[] nance = new byte[Constants.BLOCK_SIZE];
		byte[] key = new byte[Constants.KEY_SIZE];
		Cipher cipher = getGCMCipher(Cipher.ENCRYPT_MODE, key, nance);
		byte[] ciphertext = cipher.doFinal(message.getBytes());

		byte[] tag = cipher.getIV();
		byte[] encryptedKey = cryptoClient.wrapKey(KeyWrapAlgorithm.RSA_OAEP_256, key).getEncryptedKey();

		ByteArrayOutputStream blob = new ByteArrayOutputStream();
		blob.write(Constants.BLOB_HEADER);
		writeLengthPrefixed(blob, encryptedKey);
		writeLengthPrefixed(blob, nance);
		writeLengthPrefixed(blob, tag);
		writeLengthPrefixed(blob, ciphertext);
		return blob.toByteArray();
	}

	/**
	 * Decrypt the configuration
	 * 
	 * @param encryptedData
	 * @return
	 * @throws Exception
	 */
	private String decryptBuffer(byte[] encryptedData) throws Exception {

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
		UnwrapResult unwrapResult = cryptoClient.unwrapKey(KeyWrapAlgorithm.RSA_OAEP_256, encryptedKey);
		byte[] key = unwrapResult.getKey();

		Cipher cipher = getGCMCipher(Cipher.DECRYPT_MODE, key, nonce);

		byte[] decryptedMessage = cipher.doFinal(ciphertext);
		return new String(decryptedMessage, StandardCharsets.UTF_8);
	}

	/**
	 * 
	 * @param stream
	 * @return
	 * @throws IOException
	 */
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

	/**
	 * 
	 * @param input
	 * @return
	 * @throws Exception
	 */
	private String calculateMd5(String input) throws Exception {
		if (JsonUtils.isValidJson(input)) {
			MessageDigest md = MessageDigest.getInstance(Constants.MD5);
			byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(digest);
		} else
			return input;
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
			return JsonUtils.convertToString(configMap);
		} catch (JsonProcessingException e) {
			logger.error("Exception: " + e.getMessage());
		}
		return null;
	}

}
