package com.keepersecurity.secretsManager.storage.gcp;

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
 * The {@code JsonUtil} class provides utility methods for working with JSON
 * data.
 * It includes methods to validate JSON files and strings, as well as to convert
 * between JSON strings and Java Maps.
 */
public class JsonUtil {

	final static Logger logger = LoggerFactory.getLogger(JsonUtil.class);
	private static ObjectMapper objectMapper = new ObjectMapper();

	/**
	 * Private constructor to prevent instantiation of the class.
	 */
	private JsonUtil() {
		// Prevent instantiation
	}

	/**
	 * Check Json File Valid / Invalid
	 * 
	 * @param filePath Json File Path with its name.
	 * @return true if json file is valid, false if it is invalid
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
	 * @param jsonContent Check weather the jsonContent is valid or not
	 * @return true if json content is valid, false if it is invalids
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
	 * @param content String content to be converted to Map
	 * @return Map object representation of the JSON string
	 * @throws JsonProcessingException Throws JsonProcessingException if the
	 *                                 conversion fails.
	 */
	public static Map<String, Object> convertToMap(String content) throws JsonProcessingException {
		return objectMapper.readValue(content, new TypeReference<Map<String, Object>>() {
		});
	}

	/**
	 * Convert Map to String
	 * 
	 * @param configMap Map Object to be converted to String
	 * @return String representation of the Map
	 * @throws JsonProcessingException Throws JsonProcessingException if the
	 *                                 conversion fails.
	 */
	public static String convertToString(Map<String, Object> configMap) throws JsonProcessingException {
		return objectMapper.writeValueAsString(configMap);
	}
}
