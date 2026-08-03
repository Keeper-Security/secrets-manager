import os
import shlex
import tempfile
import unittest
import importlib.metadata
from unittest.mock import patch

import click_repl
from conftest import CliRunner
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_cli.__main__ import cli, _windows_safe_shlex
from keeper_secrets_manager_cli.exception import KsmCliException


class ShellTest(unittest.TestCase):

    def test_click_repl_compatible_with_installed_click(self):
        """click-repl must be compatible with the installed click version.

        click-repl 0.3.0 crashes with click>=8.2 because Context.protected_args
        was made read-only in that release. click-repl 0.3.0 assigns to it at
        _repl.py:134 during REPL command dispatch, raising AttributeError.

        setup.py pins click-repl>=0.2.0,<0.3.0 to prevent pip from resolving the
        incompatible combination. This test verifies that invariant holds in the
        installed environment.
        """
        click_version_str = importlib.metadata.version('click')
        repl_version_str = importlib.metadata.version('click-repl')

        click_major, click_minor = (int(x) for x in click_version_str.split('.')[:2])
        repl_major, repl_minor = (int(x) for x in repl_version_str.split('.')[:2])

        if (click_major, click_minor) >= (8, 2):
            self.assertLess(
                (repl_major, repl_minor),
                (0, 3),
                f"click-repl {repl_version_str} is incompatible with "
                f"click {click_version_str} (>= 8.2 makes protected_args read-only). "
                f"Pin click-repl<0.3.0 in setup.py until click-repl PR #132 is released."
            )


class ShellInvocationTestCase(unittest.TestCase):
    """Base scaffolding for tests that start `ksm shell`.

    click-repl removes the `shell` command from the click group at repl
    startup (its no-nested-shells behavior) and shell_command flips
    KsmCliException.in_a_shell; both are module-level mutations that leak
    across tests in one process, so snapshot and restore them around every
    test. Also runs each test in a temp cwd so no real keeper.ini is found.
    """

    def setUp(self):
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

        os.environ.pop("KSM_CONFIG", None)

        self.orig_commands = dict(cli.commands)
        self.orig_in_a_shell = KsmCliException.in_a_shell

    def tearDown(self):
        cli.commands.clear()
        cli.commands.update(self.orig_commands)
        KsmCliException.in_a_shell = self.orig_in_a_shell
        os.environ.pop("KSM_CONFIG", None)
        os.chdir(self.orig_dir)


class ShellBannerEncodingTest(ShellInvocationTestCase):
    """ksm shell must start even when stdout cannot encode the Unicode banner,
    e.g. cp1252 ('charmap') when output is piped or redirected on Windows."""

    def test_shell_starts_when_stdout_cannot_encode_banner(self):
        """A cp1252 stdout (charmap codec) must get a plain banner, not a crash."""
        with patch('keeper_secrets_manager_cli.__main__.update_available', return_value=None):
            runner = CliRunner(charset='cp1252')
            result = runner.invoke(cli, ['shell'], input='quit\n', catch_exceptions=False)

        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("Keeper Secrets Manager CLI", result.output,
                      "plain-text banner must be shown when the logo cannot be encoded")
        self.assertNotIn("█", result.output)

    def test_shell_keeps_unicode_banner_on_utf8_stdout(self):
        """UTF-8 capable stdout keeps the box-drawing logo."""
        with patch('keeper_secrets_manager_cli.__main__.update_available', return_value=None):
            runner = CliRunner()
            result = runner.invoke(cli, ['shell'], input='quit\n', catch_exceptions=False)

        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("█", result.output, "UTF-8 stdout must keep the Unicode logo")


class ShellSessionGlobalsTest(ShellInvocationTestCase):
    """Global options passed at `ksm shell` launch (e.g. --ini-file) must apply
    to commands run inside the shell. Options typed on an inner line still
    override the session values, for that line only."""

    def _make_client(self):
        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response()
        res.add_record(title="Init Record")
        queue = mock.ResponseQueue(client=secrets_manager)
        for _ in range(6):
            queue.add_response(res)
        return secrets_manager

    def _shell_patches(self, secrets_manager):
        client_patch = patch('keeper_secrets_manager_cli.KeeperCli.get_client',
                             return_value=secrets_manager)
        keyring_patch = patch(
            'keeper_secrets_manager_cli.keyring_config.KeyringConfigStorage.is_available',
            return_value=False)
        update_patch = patch('keeper_secrets_manager_cli.__main__.update_available',
                             return_value=None)
        return client_patch, keyring_patch, update_patch

    def test_inner_commands_inherit_session_ini_file(self):
        secrets_manager = self._make_client()
        client_patch, keyring_patch, update_patch = self._shell_patches(secrets_manager)

        with client_patch, keyring_patch, update_patch:
            runner = CliRunner()

            result = runner.invoke(cli, ['profile', 'init', '-t', 'TOKEN_ONE'],
                                   catch_exceptions=False)
            self.assertEqual(0, result.exit_code, result.output)
            # Move the ini out of the default search path so inner commands can
            # only find it through the session --ini-file.
            os.rename("keeper.ini", "custom.ini")

            result = runner.invoke(cli, ['--ini-file', 'custom.ini', 'shell'],
                                   input='profile list --json\nquit\n',
                                   catch_exceptions=False)

        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('_default', result.output,
                      "inner command must see the profiles from the session --ini-file")

    def test_inner_explicit_ini_file_overrides_for_that_line_only(self):
        secrets_manager = self._make_client()
        client_patch, keyring_patch, update_patch = self._shell_patches(secrets_manager)

        with client_patch, keyring_patch, update_patch:
            runner = CliRunner()

            result = runner.invoke(cli, ['profile', 'init', '-t', 'TOKEN_ONE'],
                                   catch_exceptions=False)
            self.assertEqual(0, result.exit_code, result.output)
            os.rename("keeper.ini", "custom.ini")

            result = runner.invoke(cli, ['profile', 'init', '-p', 'other', '-t', 'TOKEN_TWO'],
                                   catch_exceptions=False)
            self.assertEqual(0, result.exit_code, result.output)
            os.rename("keeper.ini", "other.ini")

            result = runner.invoke(
                cli, ['--ini-file', 'custom.ini', 'shell'],
                input='--ini-file other.ini profile list --json\nprofile list --json\nquit\n',
                catch_exceptions=False)

        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('other', result.output,
                      "inner explicit --ini-file must win for that line")
        self.assertIn('_default', result.output,
                      "the line after an inner override must revert to the session --ini-file")


class ShellWindowsBackslashTest(ShellInvocationTestCase):
    """ksm shell must pass backslash Windows paths to commands intact.

    click_repl 0.2.0 calls shlex.split() in POSIX mode, which treats backslash
    as an escape character and corrupts Windows paths before click sees them.
    On Windows, _windows_safe_shlex() replaces click_repl's tokenizer with one
    that preserves backslashes while still stripping quotes normally.
    """

    def setUp(self):
        super().setUp()
        self._orig_cr_shlex = click_repl.shlex

    def tearDown(self):
        click_repl.shlex = self._orig_cr_shlex
        super().tearDown()

    def test_windows_safe_shlex_preserves_backslash_paths(self):
        with patch('sys.platform', 'win32'):
            with _windows_safe_shlex():
                tokens = click_repl.shlex.split(r'--ini-file C:\fake\path.ini profile list')
        self.assertEqual(['--ini-file', r'C:\fake\path.ini', 'profile', 'list'], tokens)

    def test_windows_safe_shlex_not_applied_on_non_windows(self):
        with _windows_safe_shlex():
            self.assertIs(shlex, click_repl.shlex,
                          "click_repl.shlex must be unchanged on non-Windows platforms")

    def test_shell_backslash_path_error_shows_original_path(self):
        """A backslash path typed inside ksm shell on Windows arrives at the command intact."""
        with patch('sys.platform', 'win32'), \
             patch('keeper_secrets_manager_cli.__main__.update_available', return_value=None):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['shell'],
                input='--ini-file C:\\fake\\path.ini profile list\nquit\n'
            )

        self.assertIsInstance(
            result.exception, FileNotFoundError,
            f"expected FileNotFoundError from missing ini, got: {result.exception!r}"
        )
        self.assertIn(
            r'C:\fake\path.ini', str(result.exception),
            "error message must contain the original backslash path, not a POSIX-stripped version"
        )

    def test_shell_quoted_path_with_spaces_on_windows(self):
        """Quoted paths with spaces survive tokenization on Windows.

        posix=False alone keeps the quotes in the token value, breaking click parsing.
        """
        with patch('sys.platform', 'win32'), \
             patch('keeper_secrets_manager_cli.__main__.update_available', return_value=None):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ['shell'],
                input='--ini-file "C:\\fake path\\keeper.ini" profile list\nquit\n'
            )

        self.assertIsInstance(result.exception, FileNotFoundError)
        self.assertIn(
            'C:\\fake path\\keeper.ini', str(result.exception),
            "quoted path with spaces must arrive with quotes stripped and backslashes preserved"
        )


if __name__ == '__main__':
    unittest.main()
