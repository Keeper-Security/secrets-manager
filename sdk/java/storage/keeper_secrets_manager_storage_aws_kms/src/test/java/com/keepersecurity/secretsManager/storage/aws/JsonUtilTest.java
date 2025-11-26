package com.keepersecurity.secretsManager.storage.aws;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JsonUtil class
 */
class JsonUtilTest {

    @TempDir
    Path tempDir;

    @Test
    void testIsValidJson_WithValidJson() {
        // Given
        String validJson = "{\"key\": \"value\"}";

        // When
        boolean result = JsonUtil.isValidJson(validJson);

        // Then
        assertTrue(result, "Valid JSON should return true");
    }

    @Test
    void testIsValidJson_WithInvalidJson() {
        // Given
        String invalidJson = "{invalid json}";

        // When
        boolean result = JsonUtil.isValidJson(invalidJson);

        // Then
        assertFalse(result, "Invalid JSON should return false");
    }

    @Test
    void testIsValidJson_WithEmptyObject() {
        // Given
        String emptyObject = "{}";

        // When
        boolean result = JsonUtil.isValidJson(emptyObject);

        // Then
        assertTrue(result, "Empty JSON object should be valid");
    }

    @Test
    void testIsValidJson_WithEmptyArray() {
        // Given
        String emptyArray = "[]";

        // When
        boolean result = JsonUtil.isValidJson(emptyArray);

        // Then
        assertTrue(result, "Empty JSON array should be valid");
    }

    @Test
    void testIsValidJson_WithNestedJson() {
        // Given
        String nestedJson = "{\"outer\": {\"inner\": \"value\"}, \"array\": [1, 2, 3]}";

        // When
        boolean result = JsonUtil.isValidJson(nestedJson);

        // Then
        assertTrue(result, "Nested JSON should be valid");
    }

    @Test
    void testIsValidJson_WithNullString() {
        // When/Then
        assertThrows(Exception.class, () -> JsonUtil.isValidJson(null),
            "Null input should throw an exception");
    }

    @Test
    void testIsValidJsonFile_WithValidFile() throws IOException {
        // Given
        Path jsonFile = tempDir.resolve("valid.json");
        Files.write(jsonFile, Collections.singletonList("{\"key\": \"value\"}"), StandardCharsets.UTF_8);

        // When
        boolean result = JsonUtil.isValidJsonFile(jsonFile.toString());

        // Then
        assertTrue(result, "Valid JSON file should return true");
    }

    @Test
    void testIsValidJsonFile_WithInvalidFile() throws IOException {
        // Given
        Path invalidFile = tempDir.resolve("invalid.json");
        Files.write(invalidFile, Collections.singletonList("{invalid json}"), StandardCharsets.UTF_8);

        // When
        boolean result = JsonUtil.isValidJsonFile(invalidFile.toString());

        // Then
        assertFalse(result, "Invalid JSON file should return false");
    }

    @Test
    void testIsValidJsonFile_WithNonExistentFile() {
        // Given
        String nonExistentPath = "/non/existent/path/file.json";

        // When
        boolean result = JsonUtil.isValidJsonFile(nonExistentPath);

        // Then
        assertFalse(result, "Non-existent file should return false");
    }

    @Test
    void testConvertToMap_WithSimpleJson() throws JsonProcessingException {
        // Given
        String json = "{\"key\": \"value\", \"number\": 123}";

        // When
        Map<String, Object> result = JsonUtil.convertToMap(json);

        // Then
        assertEquals("value", result.get("key"));
        assertEquals(123, result.get("number"));
    }

    @Test
    void testConvertToMap_WithNestedJson() throws JsonProcessingException {
        // Given
        String json = "{\"outer\": {\"inner\": \"value\"}}";

        // When
        Map<String, Object> result = JsonUtil.convertToMap(json);

        // Then
        assertNotNull(result.get("outer"));
        assertTrue(result.get("outer") instanceof Map);
        @SuppressWarnings("unchecked")
        Map<String, Object> outer = (Map<String, Object>) result.get("outer");
        assertEquals("value", outer.get("inner"));
    }

    @Test
    void testConvertToMap_WithEmptyJson() throws JsonProcessingException {
        // Given
        String json = "{}";

        // When
        Map<String, Object> result = JsonUtil.convertToMap(json);

        // Then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testConvertToString_WithSimpleMap() throws JsonProcessingException {
        // Given
        Map<String, Object> map = new HashMap<>();
        map.put("key", "value");
        map.put("number", 123);

        // When
        String result = JsonUtil.convertToString(map);

        // Then
        assertNotNull(result);
        assertTrue(result.contains("\"key\""));
        assertTrue(result.contains("\"value\""));
        assertTrue(result.contains("123"));
    }

    @Test
    void testConvertToString_WithEmptyMap() throws JsonProcessingException {
        // Given
        Map<String, Object> emptyMap = new HashMap<>();

        // When
        String result = JsonUtil.convertToString(emptyMap);

        // Then
        assertEquals("{}", result);
    }

    @Test
    void testRoundTrip_MapToStringToMap() throws JsonProcessingException {
        // Given
        Map<String, Object> originalMap = new HashMap<>();
        originalMap.put("name", "test");
        originalMap.put("count", 42);
        originalMap.put("enabled", true);

        // When
        String json = JsonUtil.convertToString(originalMap);
        Map<String, Object> resultMap = JsonUtil.convertToMap(json);

        // Then
        assertEquals(originalMap.get("name"), resultMap.get("name"));
        assertEquals(originalMap.get("count"), resultMap.get("count"));
        assertEquals(originalMap.get("enabled"), resultMap.get("enabled"));
    }

    @Test
    void testConvertToMap_WithInvalidJson() {
        // Given
        String invalidJson = "{invalid}";

        // When/Then
        assertThrows(JsonProcessingException.class, () -> JsonUtil.convertToMap(invalidJson),
            "Invalid JSON should throw JsonProcessingException");
    }
}
