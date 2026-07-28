import os
import tempfile
import unittest
from unittest.mock import patch

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import FileKeyValueStorage


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
