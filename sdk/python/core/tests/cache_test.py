import os
import tempfile
import unittest

from keeper_secrets_manager_core.core import KSMCache


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


if __name__ == "__main__":
    unittest.main()
