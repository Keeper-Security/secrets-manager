import unittest
import importlib.metadata


class ShellTest(unittest.TestCase):

    def test_click_repl_compatible_with_installed_click(self):
        """KSM-818 regression: click-repl must be compatible with the installed click version.

        click-repl 0.3.0 crashes with click>=8.2 because Context.protected_args
        was made read-only in that release. click-repl 0.3.0 assigns to it at
        _repl.py:134 during REPL command dispatch, raising AttributeError.

        setup.py pins click-repl>=0.2.0,<0.3.0 to prevent pip from resolving the
        incompatible combination. This test verifies that invariant holds in the
        installed environment.

        See: https://keeper.atlassian.net/browse/KSM-818
        """
        click_version_str = importlib.metadata.version('click')
        repl_version_str = importlib.metadata.version('click-repl')

        click_major, click_minor = (int(x) for x in click_version_str.split('.')[:2])
        repl_major, repl_minor = (int(x) for x in repl_version_str.split('.')[:2])

        if (click_major, click_minor) >= (8, 2):
            self.assertLess(
                (repl_major, repl_minor),
                (0, 3),
                f"KSM-818: click-repl {repl_version_str} is incompatible with "
                f"click {click_version_str} (>= 8.2 makes protected_args read-only). "
                f"Pin click-repl<0.3.0 in setup.py until click-repl PR #132 is released."
            )


if __name__ == '__main__':
    unittest.main()
