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

import java.io.FileReader;
import java.io.IOException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

/**
 * JsonUtil class is used to check Json file and content is valid or not
 * Convert String to Map and Map to String
 */
public class JsonUtil {

	final static Logger logger = LoggerFactory.getLogger(JsonUtil.class);
	private static ObjectMapper objectMapper = new ObjectMapper();

	/**
	 * Private constructor to prevent instantiation of the class.
	 */
	private JsonUtil() {
		// Private constructor to prevent instantiation
	}

	/**
	 * Check Json File Valid / Invalid
	 * 
	 * @param filePath The path to the JSON file
	 * @return true if the file is valid JSON, false otherwise
	 */
	public static boolean isValidJsonFile(String filePath) {
		try (FileReader reader = new FileReader(filePath)) {
			JsonElement jsonElement = JsonParser.parseReader(reader);
			return jsonElement != null;
		} catch (IOException | JsonSyntaxException e) {
			logger.debug(e.getMessage());
		}
		return false;
	}

	/**
	 * Check Json content Valid / Invalid
	 * 
	 * @param jsonContent The JSON content as a string
	 * @return true if the content is valid JSON, false otherwise
	 */
	public static boolean isValidJson(String jsonContent) {
		try {
			JsonElement jsonElement = JsonParser.parseString(jsonContent);
			return jsonElement != null;
		} catch (JsonSyntaxException e) {
			logger.debug(e.getMessage());
		}
		return false;
	}

	/**
	 * Convert String to Map
	 * 
	 * @param content The JSON content as a string
	 * @return a Map representing the JSON content
	 * @throws JsonProcessingException Throws JsonProcessingException while
	 *                                 converting string to map
	 */
	public static Map<String, Object> convertToMap(String content) throws JsonProcessingException {
		return objectMapper.readValue(content, new TypeReference<Map<String, Object>>() {
		});
	}

	/**
	 * Convert Map to String
	 * 
	 * @param configMap The Map to be converted to JSON string
	 * @return A JSON string representing the Map
	 * @throws JsonProcessingException Throws JsonProcessingException while
	 *                                 converting map to string
	 */
	public static String convertToString(Map<String, Object> configMap) throws JsonProcessingException {
		return objectMapper.writeValueAsString(configMap);
	}
}
