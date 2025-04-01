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

public class JsonUtil {

	final static Logger logger = LoggerFactory.getLogger(JsonUtil.class);
	private static ObjectMapper objectMapper = new ObjectMapper();

	/**
	 * Check Json File Valid / Invalid
	 * @param filePath
	 * @return
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
	 * @param jsonContent
	 * @return
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
	 *  Convert String to Map
	 * @param content
	 * @return
	 * @throws JsonProcessingException
	 */
	public static Map<String, Object> convertToMap(String content) throws JsonProcessingException {
		return objectMapper.readValue(content, new TypeReference<Map<String, Object>>() {
		});
	}
	
	/**
	 * Convert Map to String
	 * @param configMap
	 * @return
	 * @throws JsonProcessingException
	 */
	public static String convertToString(Map<String, Object> configMap) throws JsonProcessingException {
		return objectMapper.writeValueAsString(configMap);
	}
}
