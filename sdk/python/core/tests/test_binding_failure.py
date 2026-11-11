import base64
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.dtos import RecordCreate
from keeper_secrets_manager_core.dto.payload import CreateOptions
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import FileKeyValueStorage, InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import bytes_to_base64


class BindingFailureTest(unittest.TestCase):
    """KSM-807: Partial config file should not survive a failed binding attempt."""

    def setUp(self):
        self.orig_dir = os.getcwd()

    def tearDown(self):
        os.chdir(self.orig_dir)

    def test_partial_config_removed_on_binding_failure(self):
        """Config file is deleted and a clear error is raised when the first get_secrets call fails.

        What it asserts: after SecretsManager writes partial credentials (clientId, privateKey,
        etc.) and the server rejects the token, the SDK removes the file so the user is not
        silently trapped on every subsequent run.

        Pass means: the trap is gone and the error message is actionable.
        Fail means: the partial file was left on disk (the KSM-807 bug is not fixed).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            config_path = os.path.join(tmpdir, "ksm-config.json")

            def fail_post_query(path, payload, **kwargs):
                raise KeeperError("Error: access_denied, message=Signature is invalid")

            with patch.object(SecretsManager, "_post_query", side_effect=fail_post_query):
                sm = SecretsManager(
                    token="US:FAKE_ONE_TIME_TOKEN",
                    config=FileKeyValueStorage(config_path),
                )
                with self.assertRaises(KeeperError) as ctx:
                    sm.get_secrets()

            self.assertIn(
                "Initialization failed",
                str(ctx.exception),
                "Error message should say 'Initialization failed' and direct user to get a new token",
            )
            self.assertFalse(
                os.path.exists(config_path),
                "Partial config file should be deleted after binding failure so the user is not stuck",
            )

    def test_bound_config_not_removed_on_server_error(self):
        """Config file is preserved when a fully-initialized SDK hits a transient server error.

        What it asserts: the cleanup only fires when appKey is absent (binding phase).
        A config that already has appKey must survive server errors intact — removing it
        would destroy a working configuration.

        Pass means: the bound config file still exists after the error.
        Fail means: the fix is too aggressive and nukes a legitimate config on any server error.
        """
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as fh:
            fh.write(MockConfig.make_json())
            config_path = fh.name

        try:
            sm = SecretsManager(config=FileKeyValueStorage(config_path))

            with patch.object(
                SecretsManager, "_post_query", side_effect=KeeperError("Error: server_error")
            ):
                with self.assertRaises(Exception):
                    sm.get_secrets()

            self.assertTrue(
                os.path.exists(config_path),
                "Config file must NOT be deleted when appKey is already present",
            )
        finally:
            if os.path.exists(config_path):
                os.unlink(config_path)


def new_token_key():
    """Return the key part of a new One-Time Token: 32 random bytes in URL-safe base64."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


class GetFoldersBindingFailureTest(unittest.TestCase):
    """get_folders() can also bind a new client, so a failed first call must clean up as get_secrets() does.

    create_secret_with_options(), create_folder() and update_folder() call get_folders() first when no
    folders are given, so the same cleanup applies when one of them is the first call of a new client.
    """

    def setUp(self):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        self.config_path = os.path.join(tmpdir.name, "ksm-config.json")
        self.error = KeeperError("Error: access_denied, message=Signature is invalid")
        self.paths = []

    def fail_post_query(self, path, payload, **kwargs):
        self.paths.append(path)
        raise self.error

    def assert_first_call_failure_removes_config(self, call):
        """The first call fails on get_folders: the file is removed and the get_secrets() guidance is raised."""
        with patch.object(SecretsManager, "_post_query", side_effect=self.fail_post_query):
            sm = SecretsManager(token="US:" + new_token_key(), config=FileKeyValueStorage(self.config_path))
            self.assertTrue(os.path.exists(self.config_path), "The token step writes the client keys to the file")
            with self.assertRaises(KeeperError) as ctx:
                call(sm)

        self.assertEqual(self.paths, ["get_folders"], "The first call must fail on get_folders")
        self.assertEqual(
            str(ctx.exception),
            "Initialization failed: '{}' has been removed. "
            "Please generate a new One-Time Token and try again.".format(self.config_path),
        )
        self.assertIs(ctx.exception.__cause__, self.error, "The server error must stay attached as the cause")
        self.assertFalse(os.path.exists(self.config_path), "The partial config file must be removed")

    def test_get_folders_first_call_failure_removes_partial_config(self):
        self.assert_first_call_failure_removes_config(lambda sm: sm.get_folders())

    def test_create_folder_first_call_failure_removes_partial_config(self):
        self.assert_first_call_failure_removes_config(
            lambda sm: sm.create_folder(CreateOptions("aaaaaaaaaaaaaaaaaaaaaa", None), "New folder"))

    def test_create_secret_with_options_first_call_failure_removes_partial_config(self):
        self.assert_first_call_failure_removes_config(
            lambda sm: sm.create_secret_with_options(CreateOptions("aaaaaaaaaaaaaaaaaaaaaa", None),
                                                     RecordCreate("login", "New record")))

    def test_update_folder_first_call_failure_removes_partial_config(self):
        self.assert_first_call_failure_removes_config(
            lambda sm: sm.update_folder("aaaaaaaaaaaaaaaaaaaaaa", "New name"))

    def test_get_folders_first_call_failure_with_memory_config_raises_server_error(self):
        """As for get_secrets(), only a file config is removed; other storage gets the server error."""
        with patch.object(SecretsManager, "_post_query", side_effect=self.fail_post_query):
            sm = SecretsManager(token="US:" + new_token_key(), config=InMemoryKeyValueStorage())
            with self.assertRaises(KeeperError) as ctx:
                sm.get_folders()

        self.assertIs(ctx.exception, self.error)
        self.assertIsNotNone(sm.config.get(ConfigKeys.KEY_CLIENT_ID))

    def test_bound_config_not_removed_on_get_folders_error(self):
        """A bound config (with appKey) must stay unchanged when a later get_folders() call fails."""
        with open(self.config_path, "w") as fh:
            fh.write(MockConfig.make_json())

        sm = SecretsManager(config=FileKeyValueStorage(self.config_path))
        with open(self.config_path) as fh:
            bound_config = json.load(fh)
        self.assertIn(ConfigKeys.KEY_APP_KEY.value, bound_config)

        with patch.object(SecretsManager, "_post_query", side_effect=self.fail_post_query):
            with self.assertRaises(KeeperError) as ctx:
                sm.get_folders()

        self.assertIs(ctx.exception, self.error, "A bound client must get the server error, not the guidance")
        self.assertTrue(os.path.exists(self.config_path), "Config file must NOT be deleted when appKey is present")
        with open(self.config_path) as fh:
            self.assertEqual(json.load(fh), bound_config)

    def test_new_token_binds_after_get_folders_cleanup(self):
        """After the cleanup, a new token on the same config path binds through get_folders()."""
        self.assert_first_call_failure_removes_config(lambda sm: sm.get_folders())

        token_key = new_token_key()
        app_key = os.urandom(32)
        encrypted_app_key = CryptoUtils.encrypt_aes(app_key, base64.urlsafe_b64decode(token_key + "=="))
        responses = [
            json.dumps({"encryptedAppKey": base64.urlsafe_b64encode(encrypted_app_key).decode(),
                        "folders": []}).encode(),
            json.dumps({"folders": []}).encode(),
        ]
        paths = []

        def post_query(path, payload, **kwargs):
            paths.append(path)
            return responses.pop(0)

        with patch.object(SecretsManager, "_post_query", side_effect=post_query):
            sm = SecretsManager(token="US:" + token_key, config=FileKeyValueStorage(self.config_path))
            self.assertEqual(sm.get_folders(), [])

        self.assertEqual(paths, ["get_folders", "get_folders"])
        with open(self.config_path) as fh:
            saved = json.load(fh)
        self.assertEqual(saved.get(ConfigKeys.KEY_APP_KEY.value), bytes_to_base64(app_key))
        self.assertNotIn(ConfigKeys.KEY_CLIENT_KEY.value, saved)
