package com.keepersecurity.secretsManager.storage.gcp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.HashMap;

/**
 * Unit tests for JsonUtil class
 */
class JsonUtilTest {

    @Test
    void testIsValidJsonFile_ValidJson(@TempDir Path tempDir) throws IOException {
        // Given
        Path jsonFile = tempDir.resolve("valid.json");
        String validJson = "{\"key\": \"value\", \"number\": 123}";
        Files.write(jsonFile, validJson.getBytes());

        // When
        boolean isValid = JsonUtil.isValidJsonFile(jsonFile.toString());

        // Then
        assertTrue(isValid, "Valid JSON file should return true");
    }

    @Test
    void testIsValidJsonFile_InvalidJson(@TempDir Path tempDir) throws IOException {
        // Given
        Path jsonFile = tempDir.resolve("invalid.json");
        String invalidJson = "{\"key\": \"value\", \"missing_quote: 123}";
        Files.write(jsonFile, invalidJson.getBytes());

        // When
        boolean isValid = JsonUtil.isValidJsonFile(jsonFile.toString());

        // Then
        assertFalse(isValid, "Invalid JSON file should return false");
    }

    @Test
    void testIsValidJsonFile_NonexistentFile() {
        // Given
        String nonexistentFile = "/path/that/does/not/exist.json";

        // When
        boolean isValid = JsonUtil.isValidJsonFile(nonexistentFile);

        // Then
        assertFalse(isValid, "Nonexistent file should return false");
    }

    @Test
    void testIsValidJson_ValidJsonString() {
        // Given
        String validJson = "{\"key\": \"value\", \"number\": 123, \"array\": [1, 2, 3]}";

        // When
        boolean isValid = JsonUtil.isValidJson(validJson);

        // Then
        assertTrue(isValid, "Valid JSON string should return true");
    }

    @Test
    void testIsValidJson_InvalidJsonString() {
        // Given
        String invalidJson = "{\"key\": \"value\", \"missing_quote: 123}";

        // When
        boolean isValid = JsonUtil.isValidJson(invalidJson);

        // Then
        assertFalse(isValid, "Invalid JSON string should return false");
    }

    @Test
    void testIsValidJson_EmptyString() {
        // Given
        String emptyJson = "";

        // When
        boolean isValid = JsonUtil.isValidJson(emptyJson);

        // Then
        assertTrue(isValid, "Empty string is considered valid JSON by Gson parser");
    }

    @Test
    void testConvertToMap_ValidJson() throws JsonProcessingException {
        // Given
        String jsonString = "{\"hostname\": \"keepersecurity.com\", \"clientId\": \"test123\", \"port\": 443}";

        // When
        Map<String, Object> result = JsonUtil.convertToMap(jsonString);

        // Then
        assertNotNull(result, "Result should not be null");
        assertEquals("keepersecurity.com", result.get("hostname"));
        assertEquals("test123", result.get("clientId"));
        assertEquals(443, result.get("port"));
        assertEquals(3, result.size());
    }

    @Test
    void testConvertToMap_InvalidJson() {
        // Given
        String invalidJson = "{\"key\": \"value\", \"missing_quote: 123}";

        // When/Then
        assertThrows(JsonProcessingException.class, () -> {
            JsonUtil.convertToMap(invalidJson);
        }, "Invalid JSON should throw JsonProcessingException");
    }

    @Test
    void testConvertToString_ValidMap() throws JsonProcessingException {
        // Given
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("hostname", "keepersecurity.com");
        configMap.put("clientId", "test123");
        configMap.put("port", 443);

        // When
        String result = JsonUtil.convertToString(configMap);

        // Then
        assertNotNull(result, "Result should not be null");
        assertTrue(result.contains("\"hostname\":\"keepersecurity.com\""), "Should contain hostname");
        assertTrue(result.contains("\"clientId\":\"test123\""), "Should contain clientId");
        assertTrue(result.contains("\"port\":443"), "Should contain port");
    }

    @Test
    void testConvertToString_EmptyMap() throws JsonProcessingException {
        // Given
        Map<String, Object> emptyMap = new HashMap<>();

        // When
        String result = JsonUtil.convertToString(emptyMap);

        // Then
        assertNotNull(result, "Result should not be null");
        assertEquals("{}", result, "Empty map should convert to empty JSON object");
    }

    @Test
    void testJsonRoundTrip() throws JsonProcessingException {
        // Given
        Map<String, Object> originalMap = new HashMap<>();
        originalMap.put("hostname", "keepersecurity.com");
        originalMap.put("clientId", "test123");
        originalMap.put("port", 443);
        originalMap.put("enabled", true);

        // When
        String jsonString = JsonUtil.convertToString(originalMap);
        Map<String, Object> resultMap = JsonUtil.convertToMap(jsonString);

        // Then
        assertEquals(originalMap.size(), resultMap.size(), "Maps should have same size");
        assertEquals(originalMap.get("hostname"), resultMap.get("hostname"));
        assertEquals(originalMap.get("clientId"), resultMap.get("clientId"));
        assertEquals(originalMap.get("port"), resultMap.get("port"));
        assertEquals(originalMap.get("enabled"), resultMap.get("enabled"));
    }
} 