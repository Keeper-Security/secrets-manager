import os
import re
import unittest
from conftest import CliRunner
import keeper_secrets_manager_cli
from keeper_secrets_manager_cli.__main__ import cli
from keeper_secrets_manager_cli.config import ConfigProfile
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
