import os
import tempfile
import unittest
import unittest.mock
from http import HTTPStatus

from keeper_secrets_manager_core.core import KSMCache, SecretsManager
from keeper_secrets_manager_core.dto.payload import KSMHttpResponse, TransmissionKey


class CacheTest(unittest.TestCase):

    def test_ksm_cache_dir_honored_when_set_after_import(self):
        """KSM_CACHE_DIR must be honored at call time, not only when set before import (KSM-1004).

        The module is already imported by the time this test runs (the import at the
        top of the file), with KSM_CACHE_DIR unset. Setting it now and then exercising
        the cache must place the file under the new directory.
        """
        original = os.environ.get("KSM_CACHE_DIR")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["KSM_CACHE_DIR"] = temp_dir
            try:
                payload = b"cache-bytes"
                KSMCache.save_cache(payload)

                expected_path = os.path.join(temp_dir, "ksm_cache.bin")
                self.assertTrue(
                    os.path.exists(expected_path),
                    "cache file should be written under KSM_CACHE_DIR set after import",
                )
                self.assertEqual(payload, KSMCache.get_cached_data())

                KSMCache.remove_cache_file()
                self.assertFalse(
                    os.path.exists(expected_path),
                    "remove_cache_file should delete the lazily-resolved cache file",
                )
            finally:
                if original is None:
                    os.environ.pop("KSM_CACHE_DIR", None)
                else:
                    os.environ["KSM_CACHE_DIR"] = original

    def test_kms_cache_file_name_override_is_honored(self):
        """Assigning KSMCache.kms_cache_file_name must override the cache path (backward compat).

        Before the lazy-resolution change this override governed the cache location; cache
        operations must continue to honor it when it is explicitly set.
        """
        original = KSMCache.kms_cache_file_name
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_path = os.path.join(temp_dir, "custom_cache.bin")
            KSMCache.kms_cache_file_name = custom_path
            try:
                payload = b"override-bytes"
                KSMCache.save_cache(payload)
                self.assertTrue(
                    os.path.exists(custom_path),
                    "cache file should be written to the overridden kms_cache_file_name",
                )
                self.assertEqual(payload, KSMCache.get_cached_data())

                KSMCache.remove_cache_file()
                self.assertFalse(
                    os.path.exists(custom_path),
                    "remove_cache_file should delete the overridden cache file",
                )
            finally:
                KSMCache.kms_cache_file_name = original

    def test_override_equal_to_default_text_is_still_honored(self):
        """An explicit kms_cache_file_name override must win even when its text equals the
        import-time default and KSM_CACHE_DIR is set afterward.

        Regression guard: a value-equality check treated a same-text override as "not set"
        and silently re-derived the path from KSM_CACHE_DIR. Identity-based detection fixes it.
        """
        original_override = KSMCache.kms_cache_file_name
        original_env = os.environ.get("KSM_CACHE_DIR")
        try:
            # A distinct str object whose text equals the import-time default.
            colliding_override = str(KSMCache._default_cache_file_name)
            KSMCache.kms_cache_file_name = colliding_override
            # Env set AFTER the override; the old code re-derived from this and dropped it.
            os.environ["KSM_CACHE_DIR"] = os.path.join("some", "other", "dir")

            self.assertEqual(
                colliding_override,
                KSMCache.get_cache_file_path(),
                "explicit kms_cache_file_name override must take precedence over "
                "KSM_CACHE_DIR even when its text equals the default",
            )
        finally:
            KSMCache.kms_cache_file_name = original_override
            if original_env is None:
                os.environ.pop("KSM_CACHE_DIR", None)
            else:
                os.environ["KSM_CACHE_DIR"] = original_env


    @unittest.skipIf(os.name == 'nt', "file permission bits are not meaningful on Windows")
    def test_save_cache_creates_file_owner_readable_only(self):
        original = os.environ.get("KSM_CACHE_DIR")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["KSM_CACHE_DIR"] = temp_dir
            try:
                KSMCache.save_cache(b"secret")
                path = os.path.join(temp_dir, "ksm_cache.bin")
                self.assertEqual(
                    os.stat(path).st_mode & 0o777,
                    0o600,
                    "cache file must be owner-read/write only (0600); world-readable cache exposes the transmission key",
                )
            finally:
                if original is None:
                    os.environ.pop("KSM_CACHE_DIR", None)
                else:
                    os.environ["KSM_CACHE_DIR"] = original

    @unittest.skipIf(os.name == 'nt', "file permission bits are not meaningful on Windows")
    def test_save_cache_fixes_permissions_on_existing_file(self):
        original = os.environ.get("KSM_CACHE_DIR")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["KSM_CACHE_DIR"] = temp_dir
            try:
                path = os.path.join(temp_dir, "ksm_cache.bin")
                with open(path, 'wb') as f:
                    f.write(b"old")
                os.chmod(path, 0o644)

                KSMCache.save_cache(b"new-secret")

                self.assertEqual(
                    os.stat(path).st_mode & 0o777,
                    0o600,
                    "save_cache must correct permissions even when overwriting an existing world-readable file",
                )
            finally:
                if original is None:
                    os.environ.pop("KSM_CACHE_DIR", None)
                else:
                    os.environ["KSM_CACHE_DIR"] = original


    def test_caching_post_function_returns_live_response_when_save_cache_fails(self):
        original_key = b'\xab' * 32
        transmission_key = TransmissionKey(1, original_key, b'')
        live_data = b"live-response-data"
        live_response = KSMHttpResponse(HTTPStatus.OK, live_data, None)

        with unittest.mock.patch.object(SecretsManager, 'post_function', return_value=live_response), \
             unittest.mock.patch.object(KSMCache, 'save_cache', side_effect=FileNotFoundError("bad path")):
            result = KSMCache.caching_post_function(
                "https://fake.url", transmission_key, b"payload"
            )

        self.assertEqual(result.status_code, HTTPStatus.OK)
        self.assertEqual(result.data, live_data,
                         "live response data must be returned even when save_cache raises")
        self.assertEqual(transmission_key.key, original_key,
                         "transmission_key.key must not be overwritten when the live request succeeds")


if __name__ == "__main__":
    unittest.main()
