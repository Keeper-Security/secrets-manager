import ctypes
import logging
import os
import pathlib
import subprocess
import tempfile
import types
import unittest
import unittest.mock
from ctypes import wintypes
from http import HTTPStatus

from keeper_secrets_manager_core import utils
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


class WindowsCacheAclTest(unittest.TestCase):
    """save_cache on Windows, with fake Win32 calls. Runs on every platform."""

    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.path = os.path.join(temp_dir.name, "ksm_cache.bin")
        env = unittest.mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("KSM_CONFIG_SKIP_MODE", None)
        self.calls = []
        patchers = (
            unittest.mock.patch.object(KSMCache, "kms_cache_file_name", self.path),
            unittest.mock.patch.object(utils, "_is_windows", return_value=True),
            unittest.mock.patch.object(utils, "_create_windows_owner_only_file", side_effect=self._fake_create),
            unittest.mock.patch.object(utils, "_set_windows_owner_only_acl", side_effect=self._fake_acl),
        )
        mocks = []
        for patcher in patchers:
            mocks.append(patcher.start())
            self.addCleanup(patcher.stop)
        self.create, self.acl = mocks[2], mocks[3]

    def _fake_create(self, file):
        # Like CreateFileW with CREATE_NEW: create an empty file only when no file exists.
        existed = os.path.exists(file)
        if not existed:
            with open(file, "wb"):
                pass
        self.calls.append(("create", file, existed))
        return not existed

    def _fake_acl(self, file):
        # Record the bytes that are in the file when the ACL is set.
        with open(file, "rb") as fh:
            self.calls.append(("acl", file, fh.read()))

    def _read_cache_file(self):
        with open(self.path, "rb") as fh:
            return fh.read()

    def test_new_file_is_created_with_the_acl_before_the_data(self):
        KSMCache.save_cache(b"secret data")

        self.assertEqual([("create", self.path, False), ("acl", self.path, b"")], self.calls,
                         "the file must be created with the ACL, and the ACL set while the file is empty")
        self.assertEqual(b"secret data", self._read_cache_file())

    def test_existing_file_gets_the_acl_before_the_new_data(self):
        with open(self.path, "wb") as fh:
            fh.write(b"old data")

        KSMCache.save_cache(b"new data")

        self.assertEqual([("create", self.path, True), ("acl", self.path, b"old data")], self.calls,
                         "the ACL must be set before the new data goes into the file")
        self.assertEqual(b"new data", self._read_cache_file())

    def test_each_write_sets_the_acl(self):
        KSMCache.save_cache(b"first")
        KSMCache.save_cache(b"second")

        self.assertEqual([("create", self.path, False), ("acl", self.path, b""),
                          ("create", self.path, True), ("acl", self.path, b"first")], self.calls)
        self.assertEqual(b"second", self._read_cache_file())

    def test_skip_mode_true_skips_the_acl(self):
        os.environ["KSM_CONFIG_SKIP_MODE"] = "TRUE"

        KSMCache.save_cache(b"secret data")

        self.create.assert_not_called()
        self.acl.assert_not_called()
        self.assertEqual(b"secret data", self._read_cache_file())

    def test_skip_mode_false_or_not_a_truth_value_keeps_the_acl(self):
        for value in ("FALSE", "0", "", "maybe"):
            with self.subTest(value=value):
                os.environ["KSM_CONFIG_SKIP_MODE"] = value
                self.create.reset_mock()
                self.acl.reset_mock()
                KSMCache.save_cache(b"secret data")
                self.create.assert_called_once_with(self.path)
                self.acl.assert_called_once_with(self.path)

    def test_create_failure_raises_and_writes_no_data(self):
        self.create.side_effect = PermissionError("denied")

        with self.assertRaises(PermissionError):
            KSMCache.save_cache(b"secret data")

        self.acl.assert_not_called()
        self.assertFalse(os.path.exists(self.path))

    def test_acl_failure_removes_a_new_file_and_writes_no_data(self):
        self.acl.side_effect = PermissionError("denied")

        with self.assertRaises(PermissionError):
            KSMCache.save_cache(b"secret data")

        self.assertFalse(os.path.exists(self.path), "no cache file may stay without the ACL")

    def test_acl_failure_removes_an_existing_file(self):
        with open(self.path, "wb") as fh:
            fh.write(b"old data")
        self.acl.side_effect = OSError("not supported")

        with self.assertRaises(OSError):
            KSMCache.save_cache(b"new data")

        self.assertFalse(os.path.exists(self.path), "no cache file may stay without the ACL")

    def test_no_new_file_is_created_after_the_acl_step(self):
        # If the file is gone after the ACL step, the data must not go into a new file
        # that has the ACL of the folder.
        self.acl.side_effect = os.remove

        with self.assertRaises(FileNotFoundError):
            KSMCache.save_cache(b"secret data")

        self.assertFalse(os.path.exists(self.path))

    def test_other_platforms_do_not_set_the_windows_acl(self):
        with unittest.mock.patch.object(utils, "_is_windows", return_value=False):
            KSMCache.save_cache(b"secret data")

        self.create.assert_not_called()
        self.acl.assert_not_called()
        self.assertEqual(b"secret data", self._read_cache_file())

    def test_caching_post_function_returns_the_live_response_when_the_acl_fails(self):
        live_response = KSMHttpResponse(HTTPStatus.OK, b"live-response-data", None)
        transmission_key = TransmissionKey(1, b"K" * 32, b"")
        self.acl.side_effect = PermissionError("denied")

        with unittest.mock.patch.object(SecretsManager, "post_function", return_value=live_response):
            result = KSMCache.caching_post_function("https://fake.url", transmission_key, b"payload")

        self.assertIs(result, live_response)
        self.assertFalse(os.path.exists(self.path))


class WindowsCacheAclHelperTest(unittest.TestCase):
    """The platform check and the skip mode check that save_cache uses."""

    def test_is_windows_matches_the_check_of_set_config_mode(self):
        for platform_name, expected in (("win32", True), ("linux", False), ("darwin", False), ("cygwin", False)):
            with self.subTest(platform=platform_name):
                with unittest.mock.patch.object(utils, "_platform", platform_name):
                    self.assertIs(expected, utils._is_windows())

    def test_is_config_skip_mode(self):
        for value, expected in (("TRUE", True), ("true", True), ("1", True), ("yes", True),
                                ("FALSE", False), ("0", False), ("", False), ("maybe", False), (None, False)):
            with self.subTest(value=value):
                with unittest.mock.patch.dict(os.environ):
                    os.environ.pop("KSM_CONFIG_SKIP_MODE", None)
                    if value is not None:
                        os.environ["KSM_CONFIG_SKIP_MODE"] = value
                    self.assertIs(expected, utils._is_config_skip_mode())



class WindowsAclHelperCallTest(unittest.TestCase):
    """The Win32 calls of the ACL helpers, with a fake Win32 API. Runs on every platform."""

    SID = "S-1-5-21-1-2-3-1001"
    DESCRIPTOR = 0x1000
    OWNER = 0x2000
    DACL = 0x3000
    HANDLE = 0x4000
    OTHER_OWNER = 0x5000
    FILE_DESCRIPTOR = 0x6000
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def setUp(self):
        self.calls = []
        self.last_error = 0
        self.create_result = self.HANDLE
        self.set_result = 0
        self.dacl_present = 1
        self.get_owner_result = 0
        self.file_owner = self.OTHER_OWNER

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                        ("bInheritHandle", wintypes.BOOL)]

        fake_ctypes = types.SimpleNamespace(
            c_void_p=ctypes.c_void_p, byref=ctypes.byref, sizeof=ctypes.sizeof,
            WinError=lambda code=None: OSError("Windows error {}".format(code)),
            get_last_error=lambda: self.last_error)
        kernel32 = types.SimpleNamespace(CreateFileW=self._create_file, CloseHandle=self._close_handle,
                                         LocalFree=self._local_free)
        advapi32 = types.SimpleNamespace(
            ConvertStringSecurityDescriptorToSecurityDescriptorW=self._convert_sddl,
            GetSecurityDescriptorOwner=self._get_owner, GetSecurityDescriptorDacl=self._get_dacl,
            SetNamedSecurityInfoW=self._set_named_security_info, GetNamedSecurityInfoW=self._get_named_security_info,
            EqualSid=lambda first, second: int(first.value == second.value))
        api = types.SimpleNamespace(ctypes=fake_ctypes, wintypes=wintypes, kernel32=kernel32, advapi32=advapi32,
                                    SecurityAttributes=SecurityAttributes,
                                    invalid_handle_value=self.INVALID_HANDLE_VALUE)
        for patcher in (unittest.mock.patch.object(utils, "_get_win32_security_api", return_value=api),
                        unittest.mock.patch.object(utils, "_get_windows_user_sid_string", return_value=self.SID)):
            patcher.start()
            self.addCleanup(patcher.stop)

    # Fake Win32 functions. An out parameter arrives as a byref() object; _obj is the target.
    def _convert_sddl(self, sddl, revision, descriptor, size):
        self.calls.append(("sddl", sddl, revision))
        descriptor._obj.value = self.DESCRIPTOR
        return 1

    def _get_owner(self, descriptor, owner, defaulted):
        owner._obj.value = self.OWNER
        return 1

    def _get_dacl(self, descriptor, present, dacl, defaulted):
        present._obj.value = self.dacl_present
        dacl._obj.value = self.DACL if self.dacl_present else None
        return 1

    def _set_named_security_info(self, name, object_type, information, owner, group, dacl, sacl):
        self.calls.append(("set", name, object_type, information, owner.value if owner is not None else None, group,
                           dacl.value, sacl))
        return self.set_result

    def _get_named_security_info(self, name, object_type, information, owner, group, dacl, sacl, descriptor):
        self.calls.append(("get", name, object_type, information))
        if self.get_owner_result:
            return self.get_owner_result
        owner._obj.value = self.file_owner
        descriptor._obj.value = self.FILE_DESCRIPTOR
        return 0

    def _create_file(self, name, access, share, attributes, disposition, flags, template):
        self.calls.append(("create", name, access, share, attributes._obj.lpSecurityDescriptor, disposition))
        return self.create_result

    def _close_handle(self, handle):
        self.calls.append(("close", handle))
        return 1

    def _local_free(self, memory):
        self.calls.append(("free", memory.value))

    def test_create_makes_a_new_file_with_the_owner_only_descriptor(self):
        self.assertTrue(utils._create_windows_owner_only_file("ksm_cache.bin"))

        sddl = "O:{0}D:P(A;;FA;;;{0})(A;;FA;;;BA)".format(self.SID)
        self.assertEqual([
            ("sddl", sddl, 1),
            # GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, CREATE_NEW
            ("create", os.path.abspath("ksm_cache.bin"), 0x40000000, 0x3, self.DESCRIPTOR, 1),
            ("close", self.HANDLE),
            ("free", self.DESCRIPTOR),
        ], self.calls)

    def test_create_returns_false_for_an_existing_file(self):
        self.create_result = self.INVALID_HANDLE_VALUE
        self.last_error = 80  # ERROR_FILE_EXISTS

        self.assertFalse(utils._create_windows_owner_only_file("ksm_cache.bin"))

        self.assertNotIn("close", [call[0] for call in self.calls])
        self.assertEqual(("free", self.DESCRIPTOR), self.calls[-1])

    def test_create_raises_for_another_error(self):
        self.create_result = self.INVALID_HANDLE_VALUE
        self.last_error = 5  # ERROR_ACCESS_DENIED

        with self.assertRaises(OSError):
            utils._create_windows_owner_only_file("ksm_cache.bin")

        self.assertEqual(("free", self.DESCRIPTOR), self.calls[-1])

    def _set_calls(self):
        return [call for call in self.calls if call[0] == "set"]

    def test_set_acl_sets_the_owner_when_another_account_owns_the_file(self):
        utils._set_windows_owner_only_acl("ksm_cache.bin")

        path = os.path.abspath("ksm_cache.bin")
        # 0x1 = OWNER_SECURITY_INFORMATION.
        # 0x80000005 adds DACL_SECURITY_INFORMATION and PROTECTED_DACL_SECURITY_INFORMATION.
        self.assertIn(("get", path, 1, 0x1), self.calls)
        self.assertEqual([("set", path, 1, 0x80000005, self.OWNER, None, self.DACL, None)], self._set_calls())
        self.assertEqual([("free", self.FILE_DESCRIPTOR), ("free", self.DESCRIPTOR)],
                         [call for call in self.calls if call[0] == "free"])

    def test_set_acl_keeps_the_owner_when_the_current_user_owns_the_file(self):
        # A change of the owner needs WRITE_OWNER, which a file with Modify access does not give.
        self.file_owner = self.OWNER

        utils._set_windows_owner_only_acl("ksm_cache.bin")

        # 0x80000004 = PROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, no owner
        self.assertEqual([("set", os.path.abspath("ksm_cache.bin"), 1, 0x80000004, None, None, self.DACL, None)],
                         self._set_calls())
        self.assertEqual([("free", self.FILE_DESCRIPTOR), ("free", self.DESCRIPTOR)],
                         [call for call in self.calls if call[0] == "free"])

    def test_set_acl_sets_the_owner_when_the_owner_cannot_be_read(self):
        self.get_owner_result = 5  # ERROR_ACCESS_DENIED

        utils._set_windows_owner_only_acl("ksm_cache.bin")

        self.assertEqual([("set", os.path.abspath("ksm_cache.bin"), 1, 0x80000005, self.OWNER, None, self.DACL,
                           None)], self._set_calls())
        self.assertEqual([("free", self.DESCRIPTOR)], [call for call in self.calls if call[0] == "free"])

    def test_set_acl_raises_when_windows_refuses_the_change(self):
        self.set_result = 5  # ERROR_ACCESS_DENIED

        with self.assertRaises(OSError):
            utils._set_windows_owner_only_acl("ksm_cache.bin")

        self.assertEqual(("free", self.DESCRIPTOR), self.calls[-1])

    def test_set_acl_never_sends_a_null_dacl(self):
        # A NULL DACL gives everyone full access.
        self.dacl_present = 0

        with self.assertRaises(OSError):
            utils._set_windows_owner_only_acl("ksm_cache.bin")

        self.assertNotIn("set", [call[0] for call in self.calls])
        self.assertEqual(("free", self.DESCRIPTOR), self.calls[-1])

    def test_windows_path_is_an_absolute_str(self):
        for value in ("ksm_cache.bin", b"ksm_cache.bin", pathlib.Path("ksm_cache.bin")):
            with self.subTest(value=value):
                self.assertEqual(os.path.abspath("ksm_cache.bin"), utils._windows_path(value))

def _windows_system_tool(name):
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", name)


def _windows_user_sid():
    # whoami gives the SID without the SDK code under test.
    output = subprocess.run(
        [_windows_system_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"],
        capture_output=True, text=True, check=True).stdout
    return output.strip().split(",")[-1].strip('"')


def _read_windows_dacl(path):
    """Return (owner, protected, entries) for the owner and the DACL of a file. Windows only.

    Each entry is (ace_type, ace_flags, access_mask, sid). The SID is None for an
    entry that is not an access-allowed or access-denied entry.
    """
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    class Acl(ctypes.Structure):
        _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte), ("AclSize", wintypes.WORD),
                    ("AceCount", wintypes.WORD), ("Sbz2", wintypes.WORD)]

    class AceHeader(ctypes.Structure):
        _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD)]

    class AccessAce(ctypes.Structure):
        _fields_ = [("Header", AceHeader), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]

    def sid_to_string(sid_address):
        sid_string = ctypes.c_void_p()
        if not advapi32.ConvertSidToStringSidW(sid_address, ctypes.byref(sid_string)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(sid_string.value)
        finally:
            kernel32.LocalFree(sid_string)

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    # 0x1 | 0x4 = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    result = advapi32.GetNamedSecurityInfoW(
        os.path.abspath(path), 1, 0x5, ctypes.byref(owner), None, ctypes.byref(dacl), None,
        ctypes.byref(descriptor))
    if result != 0:
        raise ctypes.WinError(result)
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise ctypes.WinError(ctypes.get_last_error())
        protected = bool(control.value & 0x1000)  # SE_DACL_PROTECTED
        entries = []
        if dacl.value:
            for index in range(Acl.from_address(dacl.value).AceCount):
                ace = ctypes.c_void_p()
                if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                    raise ctypes.WinError(ctypes.get_last_error())
                access_ace = AccessAce.from_address(ace.value)
                sid = None
                if access_ace.Header.AceType in (0, 1):  # access allowed, access denied
                    sid = sid_to_string(ace.value + AccessAce.SidStart.offset)
                entries.append((access_ace.Header.AceType, access_ace.Header.AceFlags, access_ace.Mask, sid))
        return sid_to_string(owner.value), protected, entries
    finally:
        kernel32.LocalFree(descriptor)


def _set_windows_security(path, sddl, information):
    """Test setup: set the owner and the DACL of a file from an SDDL string. Windows only.

    Returns the error code of SetNamedSecurityInfoW (0 for success).
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorOwner.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        owner, owner_defaulted = ctypes.c_void_p(), wintypes.BOOL()
        dacl, dacl_present, dacl_defaulted = ctypes.c_void_p(), wintypes.BOOL(), wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(owner_defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi32.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(dacl_present), ctypes.byref(dacl), ctypes.byref(dacl_defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        return advapi32.SetNamedSecurityInfoW(os.path.abspath(path), 1, information, owner, None, dacl, None)
    finally:
        kernel32.LocalFree(descriptor)


@unittest.skipUnless(os.name == "nt", "the Windows ACL needs Windows")
class WindowsCacheAclLiveTest(unittest.TestCase):
    """save_cache with the real Win32 ACL call. Runs only on Windows."""

    FILE_ALL_ACCESS = 0x1F01FF
    INHERITED_ACE = 0x10
    ADMINISTRATORS = "S-1-5-32-544"
    USERS = "S-1-5-32-545"
    EVERYONE = "S-1-1-0"

    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.folder = temp_dir.name
        self.path = os.path.join(self.folder, "ksm_cache.bin")
        env = unittest.mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("KSM_CONFIG_SKIP_MODE", None)
        patcher = unittest.mock.patch.object(KSMCache, "kms_cache_file_name", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.user_sid = _windows_user_sid()

    def _icacls(self, *args):
        subprocess.run([_windows_system_tool("icacls.exe")] + list(args), capture_output=True, check=True)

    def _let_users_read_new_files(self):
        # New files in the folder inherit read access for the Users group, as in a shared folder.
        self._icacls(self.folder, "/grant", "*{}:(OI)(CI)R".format(self.USERS))
        control = os.path.join(self.folder, "control.bin")
        with open(control, "wb"):
            pass
        _, _, entries = _read_windows_dacl(control)
        self.assertIn(self.USERS, [entry[3] for entry in entries if entry[1] & self.INHERITED_ACE],
                      "test setup: a new file in the folder must inherit read access for Users")

    def assertOwnerOnlyAcl(self, path):
        owner, protected, entries = _read_windows_dacl(path)
        self.assertEqual(self.user_sid, owner, "the current user must own the file")
        self.assertTrue(protected, "the DACL must not inherit entries from the folder")
        self.assertEqual(2, len(entries), entries)
        self.assertEqual(
            {(0, 0, self.FILE_ALL_ACCESS, self.user_sid), (0, 0, self.FILE_ALL_ACCESS, self.ADMINISTRATORS)},
            set(entries))

    def test_user_sid_matches_whoami(self):
        self.assertEqual(self.user_sid, utils._get_windows_user_sid_string())

    def test_create_helper_makes_the_file_owner_only_from_the_start(self):
        self._let_users_read_new_files()

        self.assertTrue(utils._create_windows_owner_only_file(self.path))

        # No SetNamedSecurityInfoW call ran, so this owner and DACL come from the creation itself.
        self.assertOwnerOnlyAcl(self.path)
        self.assertEqual(0, os.path.getsize(self.path))
        self.assertFalse(utils._create_windows_owner_only_file(self.path), "the file exists now")

    def test_new_cache_file_gets_owner_only_acl_in_a_folder_that_users_can_read(self):
        self._let_users_read_new_files()

        KSMCache.save_cache(b"secret data")

        self.assertOwnerOnlyAcl(self.path)
        self.assertEqual(b"secret data", KSMCache.get_cached_data())

    def test_existing_cache_file_that_everyone_can_read_gets_owner_only_acl(self):
        with open(self.path, "wb") as fh:
            fh.write(b"old data")
        self._icacls(self.path, "/grant", "*{}:R".format(self.EVERYONE))
        _, _, before = _read_windows_dacl(self.path)
        self.assertIn(self.EVERYONE, [entry[3] for entry in before], "test setup: Everyone must have access")

        KSMCache.save_cache(b"new data")

        self.assertOwnerOnlyAcl(self.path)
        self.assertEqual(b"new data", KSMCache.get_cached_data())

    def test_existing_cache_file_owned_by_another_account_gets_the_current_user_as_owner(self):
        with open(self.path, "wb") as fh:
            fh.write(b"old data")
        result = subprocess.run([_windows_system_tool("icacls.exe"), self.path, "/setowner",
                                 "*{}".format(self.ADMINISTRATORS)], capture_output=True)
        if result.returncode != 0:
            self.skipTest("this account cannot make Administrators the owner of a file")
        owner, _, _ = _read_windows_dacl(self.path)
        self.assertEqual(self.ADMINISTRATORS, owner, "test setup: Administrators must own the file")

        KSMCache.save_cache(b"new data")

        self.assertOwnerOnlyAcl(self.path)

    def test_existing_cache_file_that_the_user_owns_with_only_modify_access_gets_owner_only_acl(self):
        with open(self.path, "wb") as fh:
            fh.write(b"old data")
        # The current user owns the file, and the protected DACL gives the user only Modify access
        # (0x1301bf: no WRITE_DAC and no WRITE_OWNER). As the owner, the user can still set the DACL.
        # 0x80000005 = PROTECTED_DACL | DACL | OWNER security information.
        result = _set_windows_security(self.path, "O:{0}D:P(A;;0x1301bf;;;{0})".format(self.user_sid), 0x80000005)
        if result != 0:
            self.skipTest("this account cannot prepare the owner and the DACL of the file ({})".format(result))
        owner, protected, before = _read_windows_dacl(self.path)
        self.assertEqual(self.user_sid, owner, "test setup: the current user must own the file")
        self.assertTrue(protected, "test setup: the DACL must not inherit entries")
        self.assertEqual([(0, 0, 0x1301BF, self.user_sid)], before, "test setup: only the user, with Modify access")
        # Proof that the case exists for this account: a call that also sets the owner needs WRITE_OWNER and fails.
        # A failed call does not change the file.
        full_sddl = "O:{0}D:P(A;;FA;;;{0})(A;;FA;;;BA)".format(self.user_sid)
        if _set_windows_security(self.path, full_sddl, 0x80000005) == 0:
            self.skipTest("this account can change the owner without WRITE_OWNER access")
        self.assertEqual((self.user_sid, True, before), _read_windows_dacl(self.path), "test setup: no change")

        owner_checks = []
        real_check = utils._windows_file_is_owned_by

        def record_owner_check(api, file, sid):
            owner_checks.append(real_check(api, file, sid))
            return owner_checks[-1]

        with unittest.mock.patch.object(utils, "_windows_file_is_owned_by", side_effect=record_owner_check):
            KSMCache.save_cache(b"new data")

        self.assertEqual([True], owner_checks, "the SDK must find that the current user already owns the file")
        self.assertOwnerOnlyAcl(self.path)
        self.assertEqual(b"new data", KSMCache.get_cached_data())

    def test_skip_mode_keeps_the_folder_acl(self):
        self._let_users_read_new_files()
        os.environ["KSM_CONFIG_SKIP_MODE"] = "TRUE"

        KSMCache.save_cache(b"secret data")

        _, protected, entries = _read_windows_dacl(self.path)
        self.assertFalse(protected)
        self.assertIn(self.USERS, [entry[3] for entry in entries])

    def test_cache_bytes_are_written_unchanged(self):
        data = bytes(range(256)) + b"\n\r\n\x1a\x00" * 64

        KSMCache.save_cache(data)

        with open(self.path, "rb") as fh:
            self.assertEqual(data, fh.read())
        self.assertEqual(data, KSMCache.get_cached_data())

    def test_caching_post_function_writes_a_protected_cache_and_reads_it_offline(self):
        self._let_users_read_new_files()
        live_response = KSMHttpResponse(HTTPStatus.OK, b"encrypted-response", None)

        with unittest.mock.patch.object(SecretsManager, "post_function", return_value=live_response):
            result = KSMCache.caching_post_function("https://fake.url", TransmissionKey(1, b"K" * 32, b""), b"p")
        self.assertIs(result, live_response)
        self.assertOwnerOnlyAcl(self.path)

        offline_key = TransmissionKey(1, b"X" * 32, b"")
        with unittest.mock.patch.object(SecretsManager, "post_function", side_effect=ConnectionError("offline")):
            result = KSMCache.caching_post_function("https://fake.url", offline_key, b"p")
        self.assertEqual(b"encrypted-response", result.data)
        self.assertEqual(b"K" * 32, offline_key.key)


if __name__ == "__main__":
    unittest.main()
