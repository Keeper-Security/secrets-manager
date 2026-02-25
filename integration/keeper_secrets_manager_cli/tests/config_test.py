import os
import re
import sys
import unittest
from unittest.mock import patch, ANY
from conftest import CliRunner
import keeper_secrets_manager_cli
from keeper_secrets_manager_cli.__main__ import cli
from keeper_secrets_manager_cli.config import Config, ConfigProfile
from keeper_secrets_manager_cli.export import Export
from keeper_secrets_manager_core.mock import MockConfig
import tempfile
from colorama import Fore


class ConfigTest(unittest.TestCase):

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

        # Make a fake keeper.ini file.
        mock_cfg = MockConfig().make_config()
        pattern = re.compile(r'(?<!^)(?=[A-Z])')
        mock_cfg = {pattern.sub('_', x).lower(): mock_cfg[x] for x in mock_cfg.keys()}

        # Export needs ConfigProfile - hence the conversion above
        export = Export(config=ConfigProfile(**mock_cfg), file_format="ini", plain=True)
        with open("keeper.ini", "w") as fh:
            fh.write(export.run())
            fh.close()
        os.chmod("keeper.ini", 0o600)

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

    def test_config_color(self):

        runner = CliRunner()
        result = runner.invoke(cli, ['config', 'color', "--enable"], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on color enable")

        result = runner.invoke(cli, ['profile', 'list'], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on profile list")

        assert(Fore.YELLOW in result.output)

        result = runner.invoke(cli, ['config', 'color', "--disable"], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on color disable")

        result = runner.invoke(cli, ['profile', 'list'], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on profile list")

        assert(Fore.YELLOW not in result.output)

    def test_config_cache(self):

        runner = CliRunner()
        result = runner.invoke(cli, ['config', 'cache', "--enable"], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on record cache enable")

        client = keeper_secrets_manager_cli.KeeperCli()
        self.assertEqual(True, client.use_cache, "did not get True value record cache enable")

        result = runner.invoke(cli, ['config', 'cache', "--disable"], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on record cache enable")

        client = keeper_secrets_manager_cli.KeeperCli()
        self.assertEqual(False, client.use_cache, "did not get False value record cache disable")

    def test_config_record_type_directory(self):

        runner = CliRunner()
        result = runner.invoke(cli, ['config', 'record-type-dir', '-d', self.temp_dir.name], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on record cache enable")

        client = keeper_secrets_manager_cli.KeeperCli()
        self.assertEqual(self.temp_dir.name, client.record_type_dir, "did not get the record type directory")

        result = runner.invoke(cli, ['config', 'record-type-dir', "--clear"], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on record cache enable")

        client = keeper_secrets_manager_cli.KeeperCli()
        self.assertNotEqual(self.temp_dir.name, client.record_type_dir, "record type directory is not the temp dir")

    def test_config_editor(self):

        runner = CliRunner()
        result = runner.invoke(cli, ['config', 'editor',
                                     '--app', 'TextMate', '--blocking'], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on editor set")

        client = keeper_secrets_manager_cli.KeeperCli()
        self.assertEqual("TextMate", client.editor, "did not get the correct editor")
        self.assertEqual(True, client.editor_use_blocking, "did not get the correct editor blocking")

        result = runner.invoke(cli, ['config', 'editor', '--clear'], catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "did not get a success on editor clear")

        client = keeper_secrets_manager_cli.KeeperCli()
        self.assertIsNone(client.editor, "editor is not None")

        result = runner.invoke(cli, ['config', 'editor',
                                     '--app', 'code.cmd', '--process-name', "code.exe"],
                               catch_exceptions=False)
        client = keeper_secrets_manager_cli.KeeperCli()
        self.assertEqual(0, result.exit_code, "did not get a success on editor set")
        self.assertEqual("code.cmd", client.editor, "did not get the correct editor")
        self.assertEqual("code.exe", client.editor_process_name, "did not get the correct editor process")

    def test_config_show(self):

        # Just make sure no error is thrown

        runner = CliRunner()
        result = runner.invoke(cli, ['config', 'show'], catch_exceptions=False)
        print("OK", result.output)
        self.assertEqual(0, result.exit_code, "did not get a success on editor set")


@unittest.skipIf(sys.platform.startswith("win"), "Unix file permissions not applicable on Windows")
class ConfigSavePermissionsTest(unittest.TestCase):
    """Unix tests for Config.save() secure file permission handling.

    Verifies two behaviors:
    1. New files are created atomically at 0600 via os.open(), eliminating the
       TOCTOU window where open() would create a world-readable file before
       set_config_mode could correct it.
    2. set_config_mode is called unconditionally, so re-saving a file whose
       permissions were externally corrupted will always correct them.
    """

    def setUp(self):
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

    def tearDown(self):
        os.chdir(self.orig_dir)

    def _make_config(self, ini_file):
        """Return a Config with one dummy profile, ready to save."""
        config = Config(ini_file=ini_file)
        config.config.active_profile = "_default"
        config.set_profile("_default", client_id="ci", private_key="pk",
                           app_key="ak", hostname="keepersecurity.com")
        return config

    def test_save_new_file_creates_with_0600(self):
        """save() creates a new file at 0600 regardless of process umask."""
        ini_file = os.path.join(self.temp_dir.name, "new.ini")
        self.assertFalse(os.path.exists(ini_file))

        self._make_config(ini_file).save()

        mode = oct(os.stat(ini_file).st_mode)[-3:]
        self.assertEqual("600", mode, "new keeper.ini should be 0600, got {}".format(mode))

    def test_save_existing_file_with_open_permissions_corrects_to_0600(self):
        """save() on an existing 0644 file corrects permissions to 0600.

        Covers the inverted condition fix: previously file_exists is False meant
        set_config_mode only ran for new files, so an existing file with bad
        permissions would never be corrected on save.
        """
        ini_file = os.path.join(self.temp_dir.name, "existing.ini")
        with open(ini_file, "w") as fh:
            fh.write("")
        os.chmod(ini_file, 0o644)
        self.assertEqual("644", oct(os.stat(ini_file).st_mode)[-3:],
                         "precondition: file should start at 0644")

        self._make_config(ini_file).save()

        mode = oct(os.stat(ini_file).st_mode)[-3:]
        self.assertEqual("600", mode,
                         "existing 0644 keeper.ini should be corrected to 0600, got {}".format(mode))

    def test_save_existing_file_with_correct_permissions_preserves_0600(self):
        """save() on an existing 0600 file leaves permissions unchanged."""
        ini_file = os.path.join(self.temp_dir.name, "already_secure.ini")
        fd = os.open(ini_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)
        self.assertEqual("600", oct(os.stat(ini_file).st_mode)[-3:],
                         "precondition: file should start at 0600")

        self._make_config(ini_file).save()

        mode = oct(os.stat(ini_file).st_mode)[-3:]
        self.assertEqual("600", mode,
                         "existing 0600 keeper.ini should remain 0600, got {}".format(mode))


class ConfigSavePermissionsWindowsTest(unittest.TestCase):
    """Cross-platform tests that verify set_config_mode is always called by save().

    On Windows, os.open() mode is ignored — icacls (called via set_config_mode)
    is the only mechanism that restricts file access. These tests mock
    set_config_mode to confirm it is invoked for both new and existing files,
    covering the Windows code path on any platform.
    """

    def setUp(self):
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

    def tearDown(self):
        os.chdir(self.orig_dir)

    def _make_config(self, ini_file):
        config = Config(ini_file=ini_file)
        config.config.active_profile = "_default"
        config.set_profile("_default", client_id="ci", private_key="pk",
                           app_key="ak", hostname="keepersecurity.com")
        return config

    def test_set_config_mode_called_for_new_file(self):
        """save() calls set_config_mode even when creating a new file.

        On Windows, os.open mode is ignored, so set_config_mode (icacls) must
        run to restrict access on freshly created files.
        """
        ini_file = os.path.join(self.temp_dir.name, "new.ini")
        self.assertFalse(os.path.exists(ini_file))

        with patch("keeper_secrets_manager_cli.config.set_config_mode") as mock_scm:
            self._make_config(ini_file).save()
            mock_scm.assert_called_once_with(ini_file, logger=ANY)

    def test_set_config_mode_called_for_existing_file(self):
        """save() calls set_config_mode when overwriting an existing file.

        Ensures that re-saving an existing file (e.g. after a profile change)
        re-applies ACL restrictions on Windows and corrects bad Unix permissions.
        """
        ini_file = os.path.join(self.temp_dir.name, "existing.ini")
        with open(ini_file, "w") as fh:
            fh.write("")

        with patch("keeper_secrets_manager_cli.config.set_config_mode") as mock_scm:
            self._make_config(ini_file).save()
            mock_scm.assert_called_once_with(ini_file, logger=ANY)
