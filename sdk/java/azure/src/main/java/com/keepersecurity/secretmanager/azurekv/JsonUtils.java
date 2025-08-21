package com.keepersecurity.secretmanager.azurekv;

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
 * The {@code JsonUtils} class provides utility methods for working with JSON
 * data.
 * It includes methods for validating JSON files and strings, as well as
 * converting between JSON strings and Java Maps.
 */
public class JsonUtils {

	final static Logger logger = LoggerFactory.getLogger(JsonUtils.class);
	private static ObjectMapper objectMapper = new ObjectMapper();

	private JsonUtils() {
		// Prevent instantiation
	}

	/**
	 * Check Json File Valid / Invalid
	 * 
	 * @param filePath Path to the JSON file with name
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
	 * @param jsonContent String content
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
	 * @param content String content
	 * @return Converted Map
	 * @throws JsonProcessingException Throws Exception if JSON processing fails
	 */
	public static Map<String, Object> convertToMap(String content) throws JsonProcessingException {
		return objectMapper.readValue(content, new TypeReference<Map<String, Object>>() {
		});
	}

	/**
	 * Convert Map to String
	 * 
	 * @param configMap Map to be converted
	 * @return Converted String
	 * @throws JsonProcessingException Throws Exception if JSON processing fails
	 */
	public static String convertToString(Map<String, Object> configMap) throws JsonProcessingException {
		return objectMapper.writeValueAsString(configMap);
	}
}
