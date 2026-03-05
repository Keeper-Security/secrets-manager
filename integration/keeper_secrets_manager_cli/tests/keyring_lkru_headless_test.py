# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2026 Keeper Security Inc.
# Contact: sm@keepersecurity.com
#

"""
Headless Linux lkru fallback integration tests.

These tests run WITHOUT a D-Bus session, exercising the real code path where
the keyring library is installed but returns fail.Keyring. They verify that
KeyringConfigStorage.is_available() correctly falls through to the lkru utility.

They require:
  - Python keyring package installed (pip install -e ".[keyring]")
  - No active D-Bus / Secret Service session
  - KSM_LKRU_HEADLESS_TEST=1 environment variable

Run in Docker (guaranteed no D-Bus):
    docker run --rm -e KSM_LKRU_HEADLESS_TEST=1 ksm-cli-keyring-test \\
        python3 -m pytest tests/keyring_lkru_headless_test.py -v
"""

import os
import stat
import tempfile
import unittest

HEADLESS_TEST_ENABLED = os.environ.get("KSM_LKRU_HEADLESS_TEST") == "1"
SKIP_REASON = (
    "Set KSM_LKRU_HEADLESS_TEST=1 to run lkru headless tests "
    "(requires keyring installed and no active D-Bus session)"
)


@unittest.skipUnless(HEADLESS_TEST_ENABLED, SKIP_REASON)
class LkruHeadlessFallbackTest(unittest.TestCase):
    """
    Unmocked integration tests for the lkru fallback in headless Linux environments.

    These tests do NOT mock the keyring module. They rely on the real keyring
    library returning fail.Keyring when there is no D-Bus session, which is
    the same condition users experience when running the CLI on headless servers.
    """

    def setUp(self):
        os.environ.pop("KSM_CONFIG_KEYRING_UTILITY_PATH", None)

    def tearDown(self):
        os.environ.pop("KSM_CONFIG_KEYRING_UTILITY_PATH", None)

    def test_environment_is_headless(self):
        """Sanity check: confirm keyring returns fail backend (prerequisite for these tests)."""
        import keyring

        backend = keyring.get_keyring()
        self.assertIn(
            "fail",
            backend.__class__.__module__.lower(),
            f"Expected fail.Keyring in headless env, got: {backend.__class__.__module__}. "
            "Run these tests without a D-Bus session (e.g. inside Docker).",
        )

    def test_is_available_false_without_lkru(self):
        """Returns False in headless env when lkru is not installed and no env var is set."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage

        self.assertFalse(KeyringConfigStorage.is_available())

    def test_is_available_true_with_lkru_in_path(self):
        """Returns True when a real lkru executable is on PATH in headless env."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage

        with tempfile.TemporaryDirectory() as tmpdir:
            lkru_stub = os.path.join(tmpdir, "lkru")
            with open(lkru_stub, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(lkru_stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)

            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{tmpdir}:{old_path}"
            try:
                self.assertTrue(KeyringConfigStorage.is_available())
            finally:
                os.environ["PATH"] = old_path

    def test_storage_routes_to_lkru_not_fail_backend(self):
        """KeyringUtilityStorage actually routes to lkru in headless env, not fail.Keyring."""
        from keeper_secrets_manager_cli.keyring_config import KeyringUtilityStorage

        with tempfile.TemporaryDirectory() as tmpdir:
            lkru_stub = os.path.join(tmpdir, "lkru")
            with open(lkru_stub, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(lkru_stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)

            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{tmpdir}:{old_path}"
            try:
                storage = KeyringUtilityStorage(secret_name="test-headless-probe")
                self.assertFalse(
                    storage.use_python_keyring,
                    "Expected use_python_keyring=False in headless env (fail.Keyring should be rejected)",
                )
                self.assertIsNotNone(
                    storage.keyring_utility_path,
                    "Expected keyring_utility_path to be set to lkru stub",
                )
                self.assertEqual(storage.keyring_utility_path, lkru_stub)
            finally:
                os.environ["PATH"] = old_path

    def test_is_available_true_with_lkru_env_var(self):
        """Returns True when KSM_CONFIG_KEYRING_UTILITY_PATH points to a real file in headless env."""
        from keeper_secrets_manager_cli.keyring_config import KeyringConfigStorage

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            lkru_path = tmp.name

        try:
            os.environ["KSM_CONFIG_KEYRING_UTILITY_PATH"] = lkru_path
            self.assertTrue(KeyringConfigStorage.is_available())
        finally:
            os.unlink(lkru_path)
            os.environ.pop("KSM_CONFIG_KEYRING_UTILITY_PATH", None)
