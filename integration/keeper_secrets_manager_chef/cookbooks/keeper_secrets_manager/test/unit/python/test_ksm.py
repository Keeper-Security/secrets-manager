# test/unit/python/test_ksm.py
import unittest
import sys
import os
import json
import tempfile
from unittest.mock import patch, MagicMock, mock_open

# Add the files directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../files/default'))

from ksm import (
    get_env_value,
    parse_secret_notation,
    validate_auth_config,
    get_configurations,
    Constants
)

class TestKSM(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_config = {
            "authentication": ["token", "test-token-123"],
            "secrets": [
                "EG6KdJaaLG7esRZbMnfbFA/custom_field/API_KEY",
                "EG6KdJaaLG7esRZbMnfbFA/custom_field/PASSWORD > APP_PASSWORD",
                "EG6KdJaaLG7esRZbMnfbFA/file/cert.pem > file:/tmp/cert.pem"
            ],
            "folders": {
                "list_all": True
            }
        }
    
    def test_get_env_value(self):
        """Test environment variable retrieval"""
        with patch.dict(os.environ, {'TEST_VAR': 'test_value'}):
            result = get_env_value('TEST_VAR')
            self.assertEqual(result, 'test_value')
        
        # Test non-existent variable
        result = get_env_value('NON_EXISTENT_VAR')
        self.assertIsNone(result)
    
    def test_parse_secret_notation_simple(self):
        """Test parsing simple secret notation"""
        notation = "EG6KdJaaLG7esRZbMnfbFA/custom_field/API_KEY"
        keeper_notation, output_name, action_type = parse_secret_notation(notation)
        
        self.assertEqual(keeper_notation, "EG6KdJaaLG7esRZbMnfbFA/custom_field/API_KEY")
        self.assertEqual(output_name, "API_KEY")
        self.assertIsNone(action_type)
    
    def test_parse_secret_notation_with_output(self):
        """Test parsing secret notation with output specification"""
        notation = "EG6KdJaaLG7esRZbMnfbFA/custom_field/PASSWORD > APP_PASSWORD"
        keeper_notation, output_name, action_type = parse_secret_notation(notation)
        
        self.assertEqual(keeper_notation, "EG6KdJaaLG7esRZbMnfbFA/custom_field/PASSWORD")
        self.assertEqual(output_name, "APP_PASSWORD")
        self.assertIsNone(action_type)
    
    def test_parse_secret_notation_env(self):
        """Test parsing secret notation with env action"""
        notation = "EG6KdJaaLG7esRZbMnfbFA/custom_field/TOKEN > env:TOKEN"
        keeper_notation, output_name, action_type = parse_secret_notation(notation)
        
        self.assertEqual(keeper_notation, "EG6KdJaaLG7esRZbMnfbFA/custom_field/TOKEN")
        self.assertEqual(output_name, "TOKEN")
        self.assertEqual(action_type, "env")
    
    def test_parse_secret_notation_file(self):
        """Test parsing secret notation with file action"""
        notation = "EG6KdJaaLG7esRZbMnfbFA/file/cert.pem > file:/tmp/cert.pem"
        keeper_notation, output_name, action_type = parse_secret_notation(notation)
        
        self.assertEqual(keeper_notation, "EG6KdJaaLG7esRZbMnfbFA/file/cert.pem")
        self.assertEqual(output_name, "/tmp/cert.pem")
        self.assertEqual(action_type, "file")
    
    def test_validate_auth_config_token(self):
        """Test auth config validation with token"""
        # Mock environment to ensure KEEPER_CONFIG is not set
        with patch.dict(os.environ, {}, clear=True):
            auth_config = ["token", "test-token-123"]
            method, value = validate_auth_config(auth_config)
            
            self.assertEqual(method, "token")
            self.assertEqual(value, "test-token-123")
    
    def test_validate_auth_config_env_fallback(self):
        """Test auth config validation with environment fallback"""
        with patch.dict(os.environ, {'KEEPER_CONFIG': 'env-token-456'}):
            auth_config = ["token"]  # No value provided
            method, value = validate_auth_config(auth_config)
            
            self.assertEqual(method, "token")
            self.assertEqual(value, "env-token-456")
    
    def test_validate_auth_config_invalid_method(self):
        """Test auth config validation with invalid method"""
        auth_config = ["invalid_method", "some-value"]
        
        with self.assertRaises(ValueError) as context:
            validate_auth_config(auth_config)
        
        self.assertIn("Unsupported authentication method", str(context.exception))
    
    def test_get_configurations_valid_file(self):
        """Test reading valid configuration file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.test_config, f)
            temp_path = f.name
        
        try:
            config = get_configurations(temp_path)
            self.assertEqual(config, self.test_config)
        finally:
            os.unlink(temp_path)
    
    def test_get_configurations_invalid_json(self):
        """Test reading invalid JSON file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json content")
            temp_path = f.name
        
        try:
            with self.assertRaises(Exception):
                get_configurations(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_get_configurations_missing_file(self):
        """Test reading non-existent file"""
        with self.assertRaises(Exception):
            get_configurations("/non/existent/file.json")

if __name__ == '__main__':
    unittest.main() 