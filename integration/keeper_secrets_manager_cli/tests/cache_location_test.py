# -*- coding: utf-8 -*-
import os
import sys
import unittest
from unittest import mock

# _default_cache_dir resolves where ksm_cache.bin should live. It runs at package
# import time (before the SDK core is imported) so KSMCache picks up KSM_CACHE_DIR.
from keeper_secrets_manager_cli import _default_cache_dir


class DefaultCacheDirTest(unittest.TestCase):
    """KSM-1003: the CLI co-locates ksm_cache.bin with keeper.ini.

    _default_cache_dir() is a pure function of os.environ + sys.frozen. It returns
    the directory the cache should live in, or None to leave the core's default
    (current working directory) in place. The directory policy mirrors
    Config.get_default_ini_file() (KSM-980) so the cache and the ini stay together.
    """

    def setUp(self):
        # Start every case from a known-clean slate.
        for key in ("KSM_CACHE_DIR", "KSM_INI_DIR"):
            os.environ.pop(key, None)
        self._had_frozen = hasattr(sys, "frozen")
        self._frozen_val = getattr(sys, "frozen", None)
        if self._had_frozen:
            del sys.frozen

    def tearDown(self):
        for key in ("KSM_CACHE_DIR", "KSM_INI_DIR"):
            os.environ.pop(key, None)
        if self._had_frozen:
            sys.frozen = self._frozen_val
        elif hasattr(sys, "frozen"):
            del sys.frozen

    def test_pip_install_returns_none(self):
        # Not frozen, no overrides -> None, so the core keeps its CWD-relative
        # default. Proves pip/source installs are unchanged by this fix.
        self.assertIsNone(_default_cache_dir())

    def test_frozen_binary_uses_home_posix(self):
        # The bug: a frozen binary dumped the cache in CWD. Now it resolves to
        # $HOME, matching where keeper.ini lands (KSM-980).
        sys.frozen = True
        with mock.patch.object(os, "name", "posix"), \
                mock.patch.dict(os.environ, {"HOME": "/home/tester"}):
            self.assertEqual(_default_cache_dir(), "/home/tester")

    def test_frozen_binary_uses_userprofile_windows(self):
        # Windows frozen binary uses USERPROFILE, mirroring Config.is_windows().
        sys.frozen = True
        with mock.patch.object(os, "name", "nt"), \
                mock.patch.dict(os.environ, {"USERPROFILE": "C:\\Users\\tester"}):
            self.assertEqual(_default_cache_dir(), "C:\\Users\\tester")

    def test_ksm_ini_dir_takes_precedence(self):
        # If the user relocated the ini via KSM_INI_DIR, the cache follows it,
        # even in a frozen binary. Keeps the two files co-located.
        sys.frozen = True
        with mock.patch.dict(os.environ, {"KSM_INI_DIR": "/opt/ksm", "HOME": "/home/tester"}):
            self.assertEqual(_default_cache_dir(), "/opt/ksm")

    def test_explicit_cache_dir_is_honored(self):
        # An explicitly set KSM_CACHE_DIR always wins; the CLI never overrides it.
        with mock.patch.dict(os.environ, {"KSM_CACHE_DIR": "/var/cache/ksm"}):
            self.assertEqual(_default_cache_dir(), "/var/cache/ksm")


if __name__ == "__main__":
    unittest.main()
