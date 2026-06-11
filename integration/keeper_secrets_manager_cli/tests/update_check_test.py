import unittest
from unittest.mock import patch

from conftest import CliRunner
from keeper_secrets_manager_cli import __main__


class UpdateCheckTest(unittest.TestCase):

    def test_update_available_calls_check_with_keywords(self):
        """KSM-1005 regression: update_available() must call UpdateChecker.check()
        with keyword arguments.

        update_checker 1.0.0 (published to PyPI 2026-06-08, first release since
        0.18.0) made UpdateChecker.check() keyword-only:

            check(self, *, package_name, package_version)

        The CLI previously called it positionally (__main__.py:200), so every
        fresh install resolving 1.0.0 crashed `ksm shell` on launch with:

            UpdateChecker.check() takes 1 positional argument but 3 were given

        The StubUpdateChecker below mirrors the 1.0.0 keyword-only signature. A
        positional call binds against it as TypeError (this test fails); the
        keyword-argument fix passes. setup.py leaves update-checker unpinned, and
        0.18.0 uses the same parameter names, so the keyword call is compatible
        with both versions.

        See: https://keeper.atlassian.net/browse/KSM-1005
        """
        captured = {}

        class StubUpdateChecker:
            # Mirrors update_checker 1.0.0's keyword-only check() signature.
            def check(self, *, package_name, package_version):
                captured["package_name"] = package_name
                captured["package_version"] = package_version
                return None

        versions = {"keeper-secrets-manager-cli": "1.4.0"}
        with patch.object(__main__, "UpdateChecker", StubUpdateChecker):
            result = __main__.update_available("keeper-secrets-manager-cli", versions)

        self.assertIsNone(result)
        self.assertEqual(captured["package_name"], "keeper-secrets-manager-cli")
        self.assertEqual(captured["package_version"], "1.4.0")

    def test_shell_start_survives_update_check_failure(self):
        """KSM-1005 hardening: a failing update check must not stop `ksm shell`
        from starting.

        version_command (__main__.py:1393) and base_command_help (__main__.py:214)
        already wrap their update check in try/except; shell_command (1436) called
        it bare, so the KSM-1005 TypeError escaped to the top-level handler and the
        CLI exited before the shell opened. This test forces the update check to
        raise and asserts the shell still reaches the REPL.

        See: https://keeper.atlassian.net/browse/KSM-1005
        """
        def boom(*args, **kwargs):
            raise TypeError(
                "UpdateChecker.check() takes 1 positional argument but 3 were given")

        runner = CliRunner()
        with patch.object(__main__, "update_available", side_effect=boom), \
                patch.object(__main__, "Config"), \
                patch.object(__main__, "repl") as mock_repl:
            result = runner.invoke(__main__.cli, ["shell"])

        self.assertEqual(
            result.exit_code, 0,
            msg="shell did not start after update-check failure "
                f"(exit {result.exit_code}): {result.output}\n{result.exception}")
        mock_repl.assert_called_once()


if __name__ == '__main__':
    unittest.main()
