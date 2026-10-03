import base64
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.core import KSMCache

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFieldType

POST_FUNCTIONS = (KeeperAnsible._caching_post_function, KeeperAnsible._check_mode_caching_post_function)


class KeeperDrCacheTest(unittest.TestCase):
    """The DR cache replaces a failed request. That must be visible, and a missing cache must give a clear error."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "ksm_cache.bin"
        for started in (patch.dict(os.environ, {"KSM_CACHE_DIR": self.directory.name}),
                        patch.object(KSMCache, "kms_cache_file_name", str(self.path)),
                        patch("keeper_secrets_manager_ansible.display.warning")):
            mock_object = started.start()
            self.addCleanup(started.stop)
        self.warning = mock_object

    def _warnings(self):
        return [str(call.args[0]) for call in self.warning.call_args_list]

    def test_a_successful_read_saves_the_cache_only_in_a_normal_run(self):
        response = SimpleNamespace(status_code=200, data=b"fresh response")
        for post_function, saved in zip(POST_FUNCTIONS, (True, False)):
            with self.subTest(post_function=post_function.__name__):
                self.path.unlink(missing_ok=True)
                with patch.object(SecretsManager, "post_function", return_value=response):
                    result = post_function("https://unused.test", SimpleNamespace(key=b"k" * 32), "payload")
                self.assertIs(result, response)
                self.assertIs(self.path.exists(), saved)
                self.assertEqual(self._warnings(), [])

    def test_a_failed_request_uses_the_cache_with_a_warning(self):
        for post_function in POST_FUNCTIONS:
            for error in (requests.exceptions.SSLError("certificate verify failed"),
                          requests.exceptions.ConnectionError("offline"), TypeError("unexpected")):
                with self.subTest(post_function=post_function.__name__, error=type(error).__name__):
                    self.warning.reset_mock()
                    self.path.write_bytes(b"c" * 32 + b"cached response")
                    before = self.path.read_bytes()
                    transmission_key = SimpleNamespace(key=b"new key")
                    with patch.object(SecretsManager, "post_function", side_effect=error):
                        result = post_function("https://unused.test", transmission_key, "payload")
                    self.assertEqual((result.status_code, result.data), (200, b"cached response"))
                    self.assertEqual(transmission_key.key, b"c" * 32)
                    self.assertEqual(self.path.read_bytes(), before)
                    warnings = self._warnings()
                    self.assertEqual(len(warnings), 1)
                    self.assertIn("The request to the Keeper server failed ({}).".format(type(error).__name__),
                                  warnings[0])
                    self.assertIn(str(self.path), warnings[0])
                    # The text of the error stays out of the warning. It can hold the address of a proxy.
                    self.assertNotIn(str(error), warnings[0])

    def test_a_failed_request_without_a_cache_names_both_errors(self):
        for post_function in POST_FUNCTIONS:
            with self.subTest(post_function=post_function.__name__):
                self.path.unlink(missing_ok=True)
                error = requests.exceptions.SSLError("certificate verify failed")
                with patch.object(SecretsManager, "post_function", side_effect=error):
                    with self.assertRaises(ConnectionError) as context:
                        post_function("https://unused.test", SimpleNamespace(key=b"k"), "payload")
                message = str(context.exception)
                self.assertIn("The request to the Keeper server failed (SSLError)", message)
                self.assertIn("the DR cache {} cannot be read".format(self.path), message)
                self.assertIs(context.exception.__cause__, error)

    def test_a_failed_save_keeps_the_fresh_response(self):
        response = SimpleNamespace(status_code=200, data=b"fresh response")
        self.path.write_bytes(b"c" * 32 + b"cached response")
        with patch.object(SecretsManager, "post_function", return_value=response), \
                patch.object(KSMCache, "save_cache", side_effect=PermissionError("read-only")):
            result = KeeperAnsible._caching_post_function("https://unused.test", SimpleNamespace(key=b"k" * 32),
                                                          "payload")
        self.assertIs(result, response)
        self.assertTrue(any("cannot be saved" in warning for warning in self._warnings()))

    def test_an_error_response_is_returned_and_not_saved(self):
        response = SimpleNamespace(status_code=500, data=b"error")
        with patch.object(SecretsManager, "post_function", return_value=response):
            result = KeeperAnsible._caching_post_function("https://unused.test", SimpleNamespace(key=b"k" * 32),
                                                          "payload")
        self.assertIs(result, response)
        self.assertFalse(self.path.exists())

    def test_an_interrupt_is_not_replaced_by_the_cache(self):
        self.path.write_bytes(b"c" * 32 + b"cached response")
        for post_function in POST_FUNCTIONS:
            with self.subTest(post_function=post_function.__name__):
                with patch.object(SecretsManager, "post_function", side_effect=KeyboardInterrupt()):
                    with self.assertRaises(KeyboardInterrupt):
                        post_function("https://unused.test", SimpleNamespace(key=b"k"), "payload")

    def test_the_saved_cache_is_private(self):
        response = SimpleNamespace(status_code=200, data=b"fresh response")
        old_umask = os.umask(0o022)
        self.addCleanup(os.umask, old_umask)
        with patch.object(SecretsManager, "post_function", return_value=response):
            KeeperAnsible._caching_post_function("https://unused.test", SimpleNamespace(key=b"k" * 32), "payload")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)


class KeeperVaultReadTest(unittest.TestCase):
    """A read that decides a delete or a save must come from the vault, never from the DR cache."""

    def setUp(self):
        from ansible.errors import AnsibleError
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "ksm_cache.bin"
        self.path.write_bytes(b"c" * 32 + b"cached response")
        for started in (patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError),
                        patch.dict(os.environ, {"KSM_CACHE_DIR": self.directory.name}),
                        patch.object(KSMCache, "kms_cache_file_name", str(self.path)),
                        patch("keeper_secrets_manager_ansible.display.warning")):
            started.start()
            self.addCleanup(started.stop)

    @staticmethod
    def _keeper():
        from keeper_secrets_manager_core import mock
        from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
        keeper = object.__new__(KeeperAnsible)
        keeper.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()))
        keeper.client.custom_post_function = KeeperAnsible._caching_post_function
        return keeper

    def test_the_fallback_is_off_inside_a_vault_read(self):
        for post_function in POST_FUNCTIONS:
            with self.subTest(post_function=post_function.__name__), \
                    patch.object(SecretsManager, "post_function", side_effect=ConnectionError("offline")):
                with KeeperAnsible._vault_reads_only():
                    with self.assertRaisesRegex(ConnectionError, "A delete or a save needs the current vault"):
                        post_function("https://unused.test", SimpleNamespace(key=b"k"), "payload")
                result = post_function("https://unused.test", SimpleNamespace(key=b"k"), "payload")
                self.assertEqual(result.data, b"cached response")

    def test_remove_and_set_read_from_the_vault(self):
        keeper = self._keeper()
        record = SimpleNamespace(uid="RECORD_UID", title="Target", dict={"notes": "old"}, _update=lambda: None)
        allowed = []

        def get_secrets(*args, **kwargs):
            allowed.append(KeeperAnsible._dr_cache_allowed)
            return [record]

        with patch.object(keeper.client, "get_secrets", side_effect=get_secrets), \
                patch.object(keeper.client, "delete_secret",
                             return_value=[{"recordUid": "RECORD_UID", "responseCode": "ok"}]), \
                patch.object(keeper.client, "save"):
            keeper.remove_record(titles="Target")
            keeper.set_value(KeeperFieldType.NOTES, None, "new", title="Target")
        self.assertEqual(allowed, [False, False])
        self.assertTrue(KeeperAnsible._dr_cache_allowed)

    def test_a_remove_during_an_outage_fails_instead_of_using_the_cache(self):
        # A valid cached response from an earlier run, that holds another record but not the target. Read from the
        # cache, the target looks deleted already, and a remove would report a false "nothing was deleted".
        import json
        from keeper_secrets_manager_core.configkeys import ConfigKeys
        from keeper_secrets_manager_core.crypto import CryptoUtils
        from .folder_fake_server import FakeKeeperServer
        keeper = self._keeper()
        app_key = base64.b64decode(keeper.client.config.get(ConfigKeys.KEY_APP_KEY))
        state = {"folders": [{"uid": "SHARED_UID", "parent": None}],
                 "records": [{"uid": "OTHER_UID", "title": "Other", "folder": "SHARED_UID"}]}
        response = json.dumps(FakeKeeperServer._secrets(state, app_key)).encode()
        key = os.urandom(32)
        self.path.write_bytes(key + CryptoUtils.encrypt_aes(response, key))
        cached = self.path.read_bytes()
        with patch.object(SecretsManager, "post_function", side_effect=ConnectionError("offline")), \
                patch.object(SecretsManager, "delete_secret") as delete:
            for selector in ({"uids": "TARGET_UID"}, {"titles": "Target"}):
                with self.subTest(selector=selector):
                    with self.assertRaisesRegex(Exception, "A delete or a save needs the current vault"):
                        keeper.remove_record(**selector)
            delete.assert_not_called()
        self.assertEqual(self.path.read_bytes(), cached)
        self.assertTrue(KeeperAnsible._dr_cache_allowed)
