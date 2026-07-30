import os
import tempfile
import unittest
import importlib.metadata
from unittest.mock import patch

from conftest import CliRunner
from keeper_secrets_manager_cli.__main__ import cli
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


if __name__ == '__main__':
    unittest.main()
