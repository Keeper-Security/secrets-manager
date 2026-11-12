import logging
import os
import tempfile
import unittest
import unittest.mock
from http import HTTPStatus

from keeper_secrets_manager_core.core import KSMCache, SecretsManager, _default_cache_path
from keeper_secrets_manager_core.dto.payload import KSMHttpResponse, TransmissionKey
from keeper_secrets_manager_core.keeper_globals import logger_name


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

    def test_kms_cache_file_name_override_can_be_restored_to_default(self):
        """Restoring the default means assigning the sentinel back to kms_cache_file_name.

        Locks in the documented restore path: after
        KSMCache.kms_cache_file_name = KSMCache._default_cache_file_name, the override is
        treated as unset again and lazy KSM_CACHE_DIR resolution must take effect. (Assigning
        anything else, including a plain str with the default text, would keep override
        semantics; mutating _default_cache_file_name itself is never the way.)
        """
        original_override = KSMCache.kms_cache_file_name
        original_env = os.environ.get("KSM_CACHE_DIR")
        try:
            KSMCache.kms_cache_file_name = os.path.join("some", "custom", "path.bin")
            # The documented restore: assign the sentinel back.
            KSMCache.kms_cache_file_name = KSMCache._default_cache_file_name

            # After restore, lazy env resolution must work again.
            lazy_dir = os.path.join("lazy", "dir")
            os.environ["KSM_CACHE_DIR"] = lazy_dir
            self.assertEqual(
                os.path.join(lazy_dir, "ksm_cache.bin"),
                KSMCache.get_cache_file_path(),
                "restoring kms_cache_file_name to _default_cache_file_name should "
                "re-enable lazy KSM_CACHE_DIR resolution",
            )
        finally:
            KSMCache.kms_cache_file_name = original_override
            if original_env is None:
                os.environ.pop("KSM_CACHE_DIR", None)
            else:
                os.environ["KSM_CACHE_DIR"] = original_env

    def test_default_path_without_override_or_env_is_cwd(self):
        """With no override and no KSM_CACHE_DIR, the cache lives in the current working directory.

        Locks in the untouched-default contract directly: get_cache_file_path returns the
        bare filename and save_cache writes it into the CWD. Every other test exercises an
        env var or an override; without this one, a regression in the plain default would
        go unnoticed.
        """
        original_env = os.environ.get("KSM_CACHE_DIR")
        original_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                os.environ.pop("KSM_CACHE_DIR", None)
                os.chdir(temp_dir)

                self.assertEqual("ksm_cache.bin", KSMCache.get_cache_file_path())

                KSMCache.save_cache(b"default-bytes")
                self.assertTrue(
                    os.path.exists(os.path.join(temp_dir, "ksm_cache.bin")),
                    "with no override and no KSM_CACHE_DIR the cache file should be "
                    "created in the current working directory",
                )
            finally:
                os.chdir(original_cwd)
                if original_env is not None:
                    os.environ["KSM_CACHE_DIR"] = original_env

    def test_default_sentinel_text_matches_lazy_default_path(self):
        """The sentinel's text must equal what the lazy branch builds under the same env.

        Resolution ignores the sentinel's text (identity only), but kms_cache_file_name is
        a public attribute consumers may read directly; if the sentinel construction and
        _default_cache_path() drift apart (say one side re-inlines the expression), the
        attribute would advertise a path the cache methods never use. Every KSM_CACHE_DIR
        mutation in this suite restores the import-time value, so comparing against the
        helper's current output is exact.
        """
        self.assertEqual(_default_cache_path(), str(KSMCache._default_cache_file_name))


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

    def _enable_sdk_logger(self):
        # The SDK logger is shared. An earlier test can leave it disabled.
        # A disabled logger emits no records, so assertLogs and assertNoLogs cannot see them.
        # Enable it for this test.
        sdk_logger = logging.getLogger(logger_name)
        self.addCleanup(setattr, sdk_logger, "disabled", sdk_logger.disabled)
        sdk_logger.disabled = False

    def test_caching_post_function_logs_error_class_and_path_when_save_cache_fails(self):
        self._enable_sdk_logger()
        live_data = b"live-response-data"
        live_response = KSMHttpResponse(HTTPStatus.OK, live_data, None)
        cache_path = os.path.join(tempfile.gettempdir(), "ksm-cache-test", "ksm_cache.bin")

        # The text of the OSError holds the response data. The log must show the class only.
        errors = (
            FileNotFoundError("bad path"),
            OSError("short write of " + live_data.decode()),
            RuntimeError("boom"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                transmission_key = TransmissionKey(1, b'K' * 32, b'')
                with unittest.mock.patch.object(SecretsManager, 'post_function', return_value=live_response), \
                     unittest.mock.patch.object(KSMCache, 'save_cache', side_effect=error), \
                     unittest.mock.patch.object(KSMCache, 'kms_cache_file_name', cache_path), \
                     self.assertLogs(logger_name, level="WARNING") as logs:
                    result = KSMCache.caching_post_function(
                        "https://fake.url", transmission_key, b"payload"
                    )

                self.assertIs(result, live_response)
                self.assertEqual(len(logs.records), 1, "one failed cache write must log one record")
                record = logs.records[0]
                self.assertEqual(record.name, logger_name)
                self.assertEqual(record.levelname, "WARNING")
                self.assertIsNone(record.exc_info, "the log must not carry a traceback")
                self.assertEqual(
                    record.getMessage(),
                    "Cannot write the KSM cache file %s: %s" % (cache_path, type(error).__name__),
                    "the log must show only the cache path and the error class",
                )

    def test_caching_post_function_logs_ksm_cache_dir_path_when_folder_is_missing(self):
        self._enable_sdk_logger()
        live_response = KSMHttpResponse(HTTPStatus.OK, b"live-response-data", None)
        transmission_key = TransmissionKey(1, b'K' * 32, b'')

        with tempfile.TemporaryDirectory() as temp_dir:
            missing_dir = os.path.join(temp_dir, "missing")
            with unittest.mock.patch.dict(os.environ, {"KSM_CACHE_DIR": missing_dir}), \
                 unittest.mock.patch.object(SecretsManager, 'post_function', return_value=live_response), \
                 self.assertLogs(logger_name, level="WARNING") as logs:
                result = KSMCache.caching_post_function(
                    "https://fake.url", transmission_key, b"payload"
                )

        self.assertIs(result, live_response)
        self.assertEqual(len(logs.records), 1)
        message = logs.records[0].getMessage()
        self.assertIn("FileNotFoundError", message)
        self.assertIn(os.path.join(missing_dir, "ksm_cache.bin"), message)

    def test_caching_post_function_logs_nothing_when_save_cache_succeeds(self):
        self._enable_sdk_logger()
        live_response = KSMHttpResponse(HTTPStatus.OK, b"live-response-data", None)
        transmission_key = TransmissionKey(1, b'K' * 32, b'')

        with unittest.mock.patch.object(SecretsManager, 'post_function', return_value=live_response), \
             unittest.mock.patch.object(KSMCache, 'save_cache') as save_cache, \
             self.assertNoLogs(logger_name, level="WARNING"):
            result = KSMCache.caching_post_function(
                "https://fake.url", transmission_key, b"payload"
            )

        self.assertIs(result, live_response)
        save_cache.assert_called_once()


if __name__ == "__main__":
    unittest.main()
