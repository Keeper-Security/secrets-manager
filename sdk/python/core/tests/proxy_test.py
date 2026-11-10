import os
import tempfile
import unittest

import requests

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.storage import FileKeyValueStorage, InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig

from unittest.mock import patch

MOCK_PROXY_URL = "http://proxy.env:8080"

class ProxyTest(unittest.TestCase):

    def setUp(self):
        self.orig_working_dir = os.getcwd()

    def tearDown(self):
        os.chdir(self.orig_working_dir)

    def test_proxy_url_from_direct_argument(self):
        """Test that proxy_url is set from direct argument"""

        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(MockConfig.make_json())
            fh.seek(0)
            secrets_manager = SecretsManager(
                config=FileKeyValueStorage(config_file_location=fh.name),
                proxy_url=MOCK_PROXY_URL,
            )

        self.assertEqual(secrets_manager.proxy_url, MOCK_PROXY_URL)


    def test_proxy_url_if_empty(self):
        """Test that proxy_url is not set if it is empty"""
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(MockConfig.make_json())
            fh.seek(0)

            secrets_manager = SecretsManager(config=FileKeyValueStorage(config_file_location=fh.name))
            self.assertEqual(secrets_manager.proxy_url, None)

            secrets_manager = SecretsManager(config=FileKeyValueStorage(config_file_location=fh.name), proxy_url="")
            self.assertEqual(secrets_manager.proxy_url, None)

    def test_get_proxies_method(self):
        """Test that __get_proxies returns the correct object based on passed proxy_url"""

        proxies = SecretsManager._SecretsManager__get_proxies(MOCK_PROXY_URL)
        self.assertEqual(proxies, {"https": MOCK_PROXY_URL})

        proxies = SecretsManager._SecretsManager__get_proxies(None)
        self.assertEqual(proxies, None)

        proxies = SecretsManager._SecretsManager__get_proxies("")
        self.assertEqual(proxies, None)

    def test_proxy_url_passed_to_core(self):
        """Test that proxy_url is passed to the requests.post function"""
        recorded_proxy_url = None

        def mocked_post(*_args, **kwargs):
            nonlocal recorded_proxy_url
            recorded_proxy_url = kwargs.get("proxies").get("https")
            raise Exception(f"proxy_url: {recorded_proxy_url}")

        with patch("requests.post", mocked_post):
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name),
                    proxy_url=MOCK_PROXY_URL,
                )

            try:
                secrets_manager.get_secrets()
            except Exception as e:
                self.assertEqual(e.args[0], f"proxy_url: {MOCK_PROXY_URL}")

            self.assertEqual(MOCK_PROXY_URL, recorded_proxy_url)

    def test_proxy_url_passed_to_upload_file(self):
        """Test that proxy_url is passed to the requests.post in upload_file function"""
        recorded_proxy_url = None

        def mocked_post(*_args, **kwargs):
            nonlocal recorded_proxy_url
            recorded_proxy_url = kwargs.get("proxies").get("https")
            raise Exception(f"proxy_url: {recorded_proxy_url}")

        with patch("requests.post", mocked_post):
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name),
                    proxy_url=MOCK_PROXY_URL,
                )

            # Create a temporary test.txt file before passing
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as test_file:
                test_file.write("dummy content")
                test_file_path = test_file.name

            owner_record = mock.Record(uid="ipasPiqV0Lw1shtYK68_mg", record_key_bytes=b"zK{uUgw/~^x35QVu")
            try:
                secrets_manager.upload_file_path(
                    owner_record=owner_record,
                    file_path=test_file_path,
                )
            except Exception as e:
                self.assertEqual(e.args[0], f"proxy_url: {MOCK_PROXY_URL}")
            finally:
                os.unlink(test_file_path)

            self.assertEqual(MOCK_PROXY_URL, recorded_proxy_url)

    def test_proxy_url_passed_to_custom_post_function(self):
        """Test that proxy_url is passed to the custom_post_function"""
        recorded_proxy_url = None

        def mocked_post(*_args, **kwargs):
            nonlocal recorded_proxy_url
            recorded_proxy_url = kwargs.get("proxies").get("https")
            raise Exception(f"proxy_url: {recorded_proxy_url}")

        # Create a temp directory for the ksm_cache.bin file for this test only
        temp_cache_dir = tempfile.TemporaryDirectory()
        os.environ["KSM_CACHE_DIR"] = temp_cache_dir.name

        self.addCleanup(lambda: temp_cache_dir.cleanup())
        self.addCleanup(lambda: os.environ.pop("KSM_CACHE_DIR", None))

        # Create an empty ksm_cache.bin file in the temp_cache_dir
        ksm_cache_path = os.path.join(temp_cache_dir.name, "ksm_cache.bin")
        with open(ksm_cache_path, "wb") as cache_file:
            cache_file.write(b"")

        # KSM_CACHE_DIR is resolved lazily at call time (KSM-1004), so setting it
        # above is enough; no module reload is needed.
        from keeper_secrets_manager_core.core import KSMCache

        with patch("requests.post", mocked_post):
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name),
                    custom_post_function=KSMCache.caching_post_function,
                    proxy_url=MOCK_PROXY_URL,
                )

            try:
                secrets_manager.get_secrets()
            except Exception as e:
                self.assertEqual(e.args[0], f"proxy_url: {MOCK_PROXY_URL}")
            finally:
                self.assertEqual(MOCK_PROXY_URL, recorded_proxy_url)

    def test_verify_ssl_certs_passed_to_upload_file(self):
        """Test that verify_ssl_certs is passed to the requests.post in upload_file function (KSM-763)"""
        recorded_verify_ssl = None
        recorded_proxy_url = None

        def mocked_post(*_args, **kwargs):
            nonlocal recorded_verify_ssl, recorded_proxy_url
            recorded_verify_ssl = kwargs.get("verify")
            recorded_proxy_url = kwargs.get("proxies", {}).get("https") if kwargs.get("proxies") else None
            raise Exception(f"verify_ssl_certs: {recorded_verify_ssl}, proxy_url: {recorded_proxy_url}")

        with patch("requests.post", mocked_post):
            with tempfile.NamedTemporaryFile("w", delete=False) as fh:
                fh.write(MockConfig.make_json())
                fh.seek(0)
                secrets_manager = SecretsManager(
                    config=FileKeyValueStorage(config_file_location=fh.name),
                    proxy_url=MOCK_PROXY_URL,
                    verify_ssl_certs=False  # Disable SSL verification
                )

            # Create a temporary test.txt file before passing
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as test_file:
                test_file.write("dummy content")
                test_file_path = test_file.name

            owner_record = mock.Record(uid="ipasPiqV0Lw1shtYK68_mg", record_key_bytes=b"zK{uUgw/~^x35QVu")
            try:
                secrets_manager.upload_file_path(
                    owner_record=owner_record,
                    file_path=test_file_path,
                )
            except Exception as e:
                self.assertIn("verify_ssl_certs: False", e.args[0])
                self.assertIn(f"proxy_url: {MOCK_PROXY_URL}", e.args[0])
            finally:
                os.unlink(test_file_path)

            self.assertEqual(False, recorded_verify_ssl)
            self.assertEqual(MOCK_PROXY_URL, recorded_proxy_url)

    def test_verify_ssl_certs_passed_to_file_download(self):
        """Test that verify_ssl_certs and proxy_url are passed to requests.get in KeeperFile.get_file_data() (KSM-763)"""
        recorded_verify_ssl = None
        recorded_proxy_url = None

        def mocked_get(*_args, **kwargs):
            nonlocal recorded_verify_ssl, recorded_proxy_url
            recorded_verify_ssl = kwargs.get("verify")
            recorded_proxy_url = kwargs.get("proxies", {}).get("https") if kwargs.get("proxies") else None
            # Return properly encrypted content
            from keeper_secrets_manager_core.crypto import CryptoUtils
            file_key = b'\x01' * 32
            encrypted_data = CryptoUtils.encrypt_aes(b'test file content', file_key)
            class MockResponse:
                content = encrypted_data
            return MockResponse()

        from keeper_secrets_manager_core.dto.dtos import KeeperFile
        from unittest.mock import MagicMock

        # Create a minimal mock KeeperFile
        keeper_file = MagicMock(spec=KeeperFile)
        keeper_file.file_data = None
        keeper_file.f = {'url': 'https://files.example.com/test'}
        keeper_file._KeeperFile__decrypt_file_key = MagicMock(return_value=b'\x01' * 32)
        keeper_file.get_file_data = KeeperFile.get_file_data.__get__(keeper_file, KeeperFile)

        with patch("requests.get", mocked_get):
            keeper_file.get_file_data(verify_ssl_certs=False, proxy_url=MOCK_PROXY_URL)

            self.assertEqual(False, recorded_verify_ssl)
            self.assertEqual(MOCK_PROXY_URL, recorded_proxy_url)

class ProxyCredentialLeakTest(unittest.TestCase):
    """A malformed proxy URL must not put its credential into the raised error (KSM-1612).

    The password contains '#', so requests cuts the URL there and rejects the host 'usr:Zq9'.
    Its InvalidURL message echoes that fragment.
    """

    SECRET = "Zq9"
    BAD_PROXY = "http://usr:Zq9#w@127.0.0.1:9"

    def _assert_no_leak(self, exc):
        # Still an InvalidURL: the Ansible plugin and user code catch the requests exception.
        self.assertIsInstance(exc, requests.exceptions.InvalidURL)
        self.assertIsInstance(exc, KeeperError)
        self.assertNotIn(self.SECRET, str(exc))
        self.assertNotIn(self.SECRET, repr(exc))
        self.assertIsNone(exc.__cause__)
        self.assertTrue(exc.__suppress_context__)

    def _secrets_manager(self, **kwargs):
        return SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()), **kwargs)

    def test_malformed_proxy_url_argument_does_not_leak_credential(self):
        sm = self._secrets_manager(proxy_url=self.BAD_PROXY)
        with self.assertRaises(Exception) as ctx:
            sm.get_secrets()
        self._assert_no_leak(ctx.exception)

    def test_malformed_proxy_environment_variable_does_not_leak_credential(self):
        with patch.dict(os.environ, {"https_proxy": self.BAD_PROXY}):
            sm = self._secrets_manager()
            with self.assertRaises(Exception) as ctx:
                sm.get_secrets()
        self._assert_no_leak(ctx.exception)

    def test_malformed_proxy_url_on_file_download_does_not_leak_credential(self):
        from keeper_secrets_manager_core.dto.dtos import KeeperFile
        from unittest.mock import MagicMock

        keeper_file = MagicMock(spec=KeeperFile)
        keeper_file.file_data = None
        keeper_file.f = {'url': 'https://files.example.com/test'}
        keeper_file.get_file_data = KeeperFile.get_file_data.__get__(keeper_file, KeeperFile)

        with self.assertRaises(Exception) as ctx:
            keeper_file.get_file_data(proxy_url=self.BAD_PROXY)
        self._assert_no_leak(ctx.exception)
