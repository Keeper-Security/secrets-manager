package com.keepersecurity.secretmanager.aws.kms;

/**
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com
**/

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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.keepersecurity.secretsManager.core.KeyValueStorage;


import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;

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

public class AwsKeyValueStorage implements KeyValueStorage {

	   final static Logger logger = LoggerFactory.getLogger(AwsKeyValueStorage.class);

	private String defaultConfigFileLocation = "client-config.json";
	private String lastSavedConfigHash, updateConfigHash;
	private String configFileLocation;
	private String keyId;
	private Map<String, Object> configMap;

	private AWSKMSClient kmsClient;

	public AwsKeyValueStorage(String keyId, String configFileLocation, String profile, AwsSessionConfig sessionConfig, Region region)
			throws Exception {
		this.configFileLocation = configFileLocation != null ? configFileLocation
				: System.getenv("KSM_CONFIG_FILE") != null ? System.getenv("KSM_CONFIG_FILE")
						: this.defaultConfigFileLocation;
		this.keyId = keyId != null ? keyId : System.getenv("AWS_KMS_KEY_ID");
		this.configMap = new HashMap<String, Object>();
		
		if(profile!=null || sessionConfig == null) kmsClient = new AWSKMSClient(profile, region);
		else kmsClient = new AWSKMSClient(sessionConfig, region);
		
		logger.info("AWS KMS Client initiated.");
		loadConfig();
	}

	/**
	 * 
	 * @param keyId
	 * @param configFileLocation
	 * @param sessionConfig
	 * @return
	 * @throws Exception
	 */
	public static AwsKeyValueStorage getInternalStorage(String keyId, String configFileLocation, String profile,
			AwsSessionConfig sessionConfig, Region region) throws Exception {
		AwsKeyValueStorage storage = new AwsKeyValueStorage(keyId, configFileLocation, profile, sessionConfig, region);
		return storage;
	}
	
	
	/**
	 * Change key method used to encrypt config with new key
	 * @param newKeyId
	 */
	public boolean changeKey(String newKeyId) {
		logger.info("Change Key initiated");
		String configJson="";
		String oldKey = this.keyId;
		AWSKMSClient oldkmsClient = this.kmsClient;
		
		try {
			this.keyId = newKeyId;
			save(configJson, configMap);
			logger.info("Encrypted using new KeyId");
			return true;
		}catch(Exception e) {
			this.keyId = oldKey;
			this.kmsClient = oldkmsClient;
			logger.error("Exception: "+e.getMessage());
		}
		return false;
	}

	/**
	 * 
	 * @throws Exception
	 */
	private void loadConfig() throws Exception {
		File file = new File(configFileLocation);
        if (file.exists()) {
        	if (file.length() == 0) {
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
				String configJson = Files.readString(Paths.get(configFileLocation));
				lastSavedConfigHash = calculateMd5(configJson);
				configMap = JsonUtil.convertToMap(configJson);
				saveConfig(configMap);
			}
        }
        
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
			logger.error("Exception:"+e.getMessage());
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
				logger.error("Exception:"+e.getMessage());
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
		if (kmsClient.isSymmetricKey(keyId)) {
			byte[] encrypted = kmsClient.encrypt(SdkBytes.fromUtf8String(message), keyId);
			ByteArrayOutputStream blob = new ByteArrayOutputStream();
			writeLengthPrefixed(blob, encrypted);
			return blob.toByteArray();
		} else {
			byte[] nance = new byte[Constants.BLOCK_SIZE];
			byte[] key = new byte[Constants.KEY_SIZE];
			Cipher cipher = getGCMCipher(Cipher.ENCRYPT_MODE, key, nance);
			byte[] ciphertext = cipher.doFinal(message.getBytes());

			byte[] tag = cipher.getIV();
			byte[] encryptedKey = kmsClient.encrypt(SdkBytes.fromByteArray(key), keyId);

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
		if (kmsClient.isSymmetricKey(keyId)) {
			ByteArrayInputStream blobInputStream = new ByteArrayInputStream(encryptedData);
			byte[] encrypted = readLengthPrefixed(blobInputStream);
			byte[] decryptedMessage = kmsClient.decrypt(encrypted, keyId).asByteArray();
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
			byte[] key = kmsClient.decrypt(encryptedKey, keyId).asByteArray();
			Cipher cipher = getGCMCipher(Cipher.DECRYPT_MODE, key, nonce);

			byte[] decryptedMessage = cipher.doFinal(ciphertext);
			return new String(decryptedMessage, StandardCharsets.UTF_8);
		}
	}
	
	/**
	 * Decrypt the encrypted config, autosave=true/false
	 * @param autosave
	 * @return
	 * @throws Exception
	 */
	public String decryptConfig(boolean autosave) throws Exception {
		String decryptedContent=null;
		if (!JsonUtil.isValidJsonFile(configFileLocation)) {
			 decryptedContent = decryptBuffer(readEncryptedJsonFile());
			 if(autosave) {
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
    	 if (configMap.get(key) == null) return null;
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
        if (configMap.get(key) == null) return null;
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
            try{loadConfig();}catch(Exception e){logger.error("Failed to load config file.", e);}
        }
        try {
            return JsonUtil.convertToString(configMap);
        } catch (JsonProcessingException e) {
            logger.error("Exception: " + e.getMessage());
        }
        return null;
    }

}
