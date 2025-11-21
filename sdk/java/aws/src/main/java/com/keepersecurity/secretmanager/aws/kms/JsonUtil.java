package com.keepersecurity.secretmanager.aws.kms;

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
	}

	/**
	 * Check Json File Valid / Invalid
	 * 
	 * @param filePath File path along with file name
	 * @return boolean
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
	 * @param jsonContent Check Json content
	 * @return boolean
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
	 * @param content Convert String content to Map
	 * @return Converted string content into Map
	 * @throws JsonProcessingException Throws exception if any error occurs during
	 *                                 conversion
	 */
	public static Map<String, Object> convertToMap(String content) throws JsonProcessingException {
		return objectMapper.readValue(content, new TypeReference<Map<String, Object>>() {
		});
	}

	/**
	 * Convert Map to String
	 * 
	 * @param configMap Convert Map to String
	 * @return Converted Map to String
	 * @throws JsonProcessingException Throws exception if any error occurs during
	 *                                 conversion
	 */
	public static String convertToString(Map<String, Object> configMap) throws JsonProcessingException {
		return objectMapper.writeValueAsString(configMap);
	}
}