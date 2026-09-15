import sys
import unittest
from unittest.mock import patch

from keeper_secrets_manager_cli import __main__


class WindowsExpandArgsTest(unittest.TestCase):

    def test_main_disables_click_windows_arg_expansion(self):
        """main() must invoke the click group with windows_expand_args=False.

        click >= 8.0 expands every sys.argv argument on Windows before parsing
        (BaseCommand.main -> _expand_args: os.path.expanduser, then
        os.path.expandvars, then glob). ntpath.expandvars expands %VAR%/$VAR
        and collapses $$ to $, so secret values passed as arguments were
        silently corrupted before storage (KSM-1186):

            'password=a$$b'   was stored as 'a$b'
            'login=x%OS%y'    was stored as 'xWindows_NTy'

        click 8.0.1 added the windows_expand_args parameter as the supported
        opt-out; main() must pass it as False.

        CliRunner.invoke() bypasses BaseCommand.main() entirely (it calls
        Command.invoke via make_context), so the corruption cannot be observed
        in-process — which is exactly how it evaded the unit suite. This test
        therefore asserts the wiring of main() itself; end-to-end byte
        fidelity is covered by the release regression suite, which drives the
        packaged CLI in a real subprocess on Windows.
        """
        captured = {}

        def fake_group_main(*args, **kwargs):
            captured.update(kwargs)

        with patch.object(__main__.cli, "main", side_effect=fake_group_main):
            with patch.object(sys, "argv", ["ksm", "version"]):
                __main__.main()

        self.assertIn("windows_expand_args", captured,
                      "main() no longer passes windows_expand_args to the click "
                      "group; Windows argv expansion would corrupt secret values "
                      "again (KSM-1186)")
        self.assertIs(captured["windows_expand_args"], False,
                      "main() must pass windows_expand_args=False (KSM-1186)")


if __name__ == "__main__":
    unittest.main()
