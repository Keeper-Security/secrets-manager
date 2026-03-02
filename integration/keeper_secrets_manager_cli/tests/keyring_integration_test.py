# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021-2026 Keeper Security Inc.
# Contact: sm@keepersecurity.com
#

"""
Integration tests for keyring-based configuration storage.

These tests require a real Secret Service backend (dbus + gnome-keyring).
They are skipped unless KSM_KEYRING_INTEGRATION=1 is set.

Run locally:
    dbus-run-session -- bash -c "
        echo '' | gnome-keyring-daemon --unlock --components=secrets,keyring
        KSM_KEYRING_INTEGRATION=1 python -m pytest tests/keyring_integration_test.py -v
    "
"""

import os
import unittest

INTEGRATION_ENABLED = os.environ.get("KSM_KEYRING_INTEGRATION") == "1"
SKIP_REASON = "Set KSM_KEYRING_INTEGRATION=1 to run keyring integration tests (requires dbus + gnome-keyring)"

# Isolate integration test entries from production data
TEST_APP_NAME = "KSM-cli-integration-test"


@unittest.skipUnless(INTEGRATION_ENABLED, SKIP_REASON)
class KeyringIntegrationTest(unittest.TestCase):
    """Integration tests using a real OS keyring backend (no mocks)."""

    def setUp(self):
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage
        self.storage = KeyringConfigStorage(keyring_application_name=TEST_APP_NAME)
        # Clean up any leftover entries from a previous run
        self.storage.clear_all()

    def tearDown(self):
        try:
            self.storage.clear_all()
        except Exception:
            pass

    def test_keyring_library_importable(self):
        """[keyring] extra is installed: import keyring succeeds without ImportError."""
        import keyring  # noqa: F401

    def test_is_available_with_real_backend(self):
        """KeyringConfigStorage.is_available() returns True with gnome-keyring running."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage

        self.assertTrue(
            KeyringConfigStorage.is_available(),
            "is_available() must return True when gnome-keyring is running; "
            "got False — check that gnome-keyring-daemon is unlocked and "
            "the active backend is not fail.Keyring",
        )

    def test_save_load_roundtrip(self):
        """save_profile + load_profile returns identical data via Secret Service."""
        profile_data = {
            "clientId": "integration-test-client",
            "hostname": "keepersecurity.com",
            "appKey": "test-app-key",
            "privateKey": "test-private-key",
        }

        self.storage.save_profile("test-profile", profile_data)

        loaded = self.storage.load_profile("test-profile")

        self.assertIsNotNone(loaded, "load_profile returned None after save_profile")
        self.assertEqual(profile_data["clientId"], loaded["clientId"])
        self.assertEqual(profile_data["hostname"], loaded["hostname"])
        self.assertEqual(profile_data["appKey"], loaded["appKey"])
        self.assertEqual(profile_data["privateKey"], loaded["privateKey"])

        # Integrity hash must have been stored alongside the profile
        import keyring as _keyring
        integrity_value = _keyring.get_password(TEST_APP_NAME, "ksm-cli-profile-test-profile-integrity")
        self.assertIsNotNone(integrity_value, "Integrity hash was not stored after save_profile")
        self.assertTrue(len(integrity_value) > 0, "Integrity hash is empty")

    def test_list_and_delete_profiles(self):
        """list_profiles returns saved name; delete_profile removes it and its integrity hash."""
        profile_data = {"clientId": "list-test-id", "hostname": "keepersecurity.com"}

        self.storage.save_profile("list-test", profile_data)
        self.storage.add_profile_to_list("list-test")

        profiles = self.storage.list_profiles()
        self.assertIn("list-test", profiles, "list_profiles did not return the saved profile name")

        self.storage.delete_profile("list-test")

        profiles_after = self.storage.list_profiles()
        self.assertNotIn("list-test", profiles_after, "delete_profile did not remove the profile from the list")

        # Integrity hash entry must also be absent after deletion
        import keyring as _keyring
        remaining = _keyring.get_password(TEST_APP_NAME, "ksm-cli-profile-list-test-integrity")
        self.assertIsNone(remaining, "Integrity hash entry was not deleted alongside the profile")

    def test_profile_name_rejected_before_keyring_write(self):
        """KSM-829 regression: invalid profile names raise KsmCliException without touching keyring."""
        from keeper_secrets_manager_cli.exception import KsmCliException
        import keyring as _keyring

        invalid_names = [
            "invalid/name",
            "has spaces",
            "../traversal",
            "",
            "a" * 65,  # exceeds 64-char limit
        ]

        for name in invalid_names:
            with self.subTest(name=repr(name)):
                with self.assertRaises(KsmCliException):
                    self.storage.save_profile(name, {"clientId": "should-not-reach-keyring"})

                # Confirm nothing was written to the keyring for this invalid name
                escaped = name.replace("/", "_").replace(" ", "_").replace(".", "_")
                stored = _keyring.get_password(TEST_APP_NAME, "ksm-cli-profile-%s" % escaped)
                self.assertIsNone(stored, "Keyring entry was created for invalid profile name %r" % name)


if __name__ == "__main__":
    unittest.main()
