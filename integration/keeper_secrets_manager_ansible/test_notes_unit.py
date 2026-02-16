#!/usr/bin/env python3
"""
Unit test for notes retrieval functionality - tests the specific code we modified
"""

import sys
import os

# Add the package to Python path
sys.path.insert(0, os.path.dirname(__file__))

from keeper_secrets_manager_ansible import KeeperFieldType
from keeper_secrets_manager_core.dto.dtos import Record as KeeperRecord
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core import utils

def create_mock_record_with_notes():
    """Create a mock Keeper record with notes for testing"""

    # Create a minimal record dict
    record_dict = {
        'recordUid': 'test123',
        'data': None,  # We'll mock the encrypted data
        'revision': 1,
        'isEditable': True,
    }

    # Create fake secret key for encryption
    fake_secret_key = bytes([0] * 32)  # 32 bytes of zeros

    # Create the decrypted record data
    record_data = {
        'title': 'Test Record',
        'type': 'login',
        'fields': [
            {
                'type': 'password',
                'value': ['TESTPASSWORD']
            }
        ],
        'notes': 'These are my test notes'
    }

    # Convert to JSON
    record_json = utils.dict_to_json(record_data)

    # Encrypt the record data
    encrypted_data = CryptoUtils.encrypt_aes(utils.string_to_bytes(record_json), fake_secret_key)
    record_dict['data'] = utils.bytes_to_base64(encrypted_data)

    # Create the Record object
    record = KeeperRecord(record_dict, fake_secret_key)

    return record

def test_notes_field_type_enum():
    """Test that NOTES field type is properly defined"""
    print("Testing NOTES field type enum...")

    # Check that NOTES enum exists
    assert hasattr(KeeperFieldType, 'NOTES'), "NOTES not found in KeeperFieldType enum"
    assert KeeperFieldType.NOTES.value == 'notes', f"NOTES value should be 'notes', got '{KeeperFieldType.NOTES.value}'"

    # Check that get_enum works with 'notes'
    enum_value = KeeperFieldType.get_enum('notes')
    assert enum_value == KeeperFieldType.NOTES, f"get_enum('notes') should return NOTES enum, got {enum_value}"

    print("✓ NOTES enum is properly defined")
    return True

def test_notes_in_record():
    """Test that notes can be accessed from a Keeper record"""
    print("\nTesting notes access from record...")

    # Create a mock record with notes
    record = create_mock_record_with_notes()

    # Verify the record has notes
    assert hasattr(record, 'dict'), "Record should have 'dict' attribute"
    assert 'notes' in record.dict, "Record dict should contain 'notes' field"

    notes_value = record.dict.get('notes')
    assert notes_value == 'These are my test notes', f"Expected 'These are my test notes', got '{notes_value}'"

    print(f"✓ Successfully accessed notes from record: '{notes_value}'")
    return True

def test_allowed_fields():
    """Test that 'notes' is in ALLOWED_FIELDS"""
    print("\nTesting ALLOWED_FIELDS includes notes...")

    from keeper_secrets_manager_ansible import KeeperAnsible

    assert 'notes' in KeeperAnsible.ALLOWED_FIELDS, "notes should be in ALLOWED_FIELDS"
    print(f"✓ ALLOWED_FIELDS contains: {KeeperAnsible.ALLOWED_FIELDS}")

    return True

def main():
    """Run all tests"""
    print("="*60)
    print("NOTES FIELD UNIT TESTS")
    print("="*60)

    try:
        # Run all tests
        all_passed = True
        all_passed &= test_notes_field_type_enum()
        all_passed &= test_notes_in_record()
        all_passed &= test_allowed_fields()

        print("\n" + "="*60)
        if all_passed:
            print("✅ ALL UNIT TESTS PASSED")
            print("="*60)
            return 0
        else:
            print("❌ SOME TESTS FAILED")
            print("="*60)
            return 1

    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
