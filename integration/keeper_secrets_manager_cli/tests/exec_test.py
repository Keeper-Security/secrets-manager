import os
import unittest
from unittest.mock import patch
from click.testing import CliRunner
import tempfile
import re

from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_cli.__main__ import cli
from keeper_secrets_manager_cli.profile import Profile

from sys import platform


class ExecTest(unittest.TestCase):

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)
        self.delete_me = []

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

        # Github Action does like how I'm doing temp files. So we manually have to delete them. This is to avoid
        # Cannot execute command: [Errno 26] Text file busy: '/tmp/tmpsp3v5vqb'
        for item in self.delete_me:
            os.unlink(item)

        # Remove vars add to environment. This prevent tests from interfering with others.
        for key in os.environ.keys():
            if key.startswith("EXEC_") is True:
                os.environ.pop(key, None)

    def test_cmd(self):

        # Log level set in this one, nothing below INFO should appear.
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.custom_field("password", "My Password 1")

        queue = mock.ResponseQueue(client=secrets_manager)
        # Profile init
        queue.add_response(res)

        # One for each var ... until we begin to cache.
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as \
                mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Make a temp shell script. Call it .BAT so it works under windows, Linux won't care.
            with tempfile.NamedTemporaryFile(delete=False, suffix=".BAT") as script:
                self.delete_me.append(script.name)
                if platform == "win32":
                    the_script = [
                        "@echo off",
                        "setlocal enableDelayedExpansion",
                        "echo '%EXEC_VAR_ONE%'",
                        "echo '%EXEC_VAR_TWO%'",
                        "echo '%EXEC_NOT_ONE%'"
                    ]
                else:
                    the_script = [
                        "#!/bin/sh",
                        "echo ${EXEC_VAR_ONE}",
                        "echo ${EXEC_VAR_TWO}",
                        "echo ${EXEC_NOT_ONE}"
                    ]
                script.write("\n".join(the_script).encode())
                script.close()
                os.chmod(script.name, 0o777)

                os.environ["EXEC_VAR_ONE"] = "{}://{}/{}/{}".format(SecretsManager.notation_prefix, one.uid, "field",
                                                               "login")
                os.environ["EXEC_VAR_TWO"] = "{}://{}/{}/{}".format(SecretsManager.notation_prefix, one.uid,
                                                                    "custom_field", "password")
                os.environ["EXEC_BAD_ONE"] = "{}THIS IS BAD".format(SecretsManager.notation_prefix)
                os.environ["EXEC_NOT_ONE"] = "BLAH"

                runner = CliRunner()
                result = runner.invoke(cli, ['exec', '--capture-output', script.name], catch_exceptions=False)
                print("-------------------")
                print(result.output)
                print("-------------------")
                self.assertIsNotNone(re.search('My Login 1', result.output, flags=re.MULTILINE),
                                     "did not find the login")
                self.assertIsNotNone(re.search('My Password 1', result.output, flags=re.MULTILINE),
                                     "did not find the password")
                self.assertIsNotNone(re.search('BLAH', result.output, flags=re.MULTILINE),
                                     "did not find the not one")

    def test_cmd_inline(self):

        # Log level set in this one, nothing below INFO should appear.
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "PASS")
        one.custom_field("password", "My Password 1")

        queue = mock.ResponseQueue(client=secrets_manager)
        # Profile init
        queue.add_response(res)

        # One for each var ... until we begin to cache.
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Make a temp shell script
            with tempfile.NamedTemporaryFile(delete=False, suffix=".BAT") as script:
                self.delete_me.append(script.name)
                if platform == "win32":
                    the_script = [
                        "@echo off",
                        "setlocal enableDelayedExpansion",
                        "echo '%EXEC_VAR_ONE%'",
                        "echo '%EXEC_VAR_TWO%'",
                        "echo '%~1'"
                    ]
                else:
                    the_script = [
                        "#!/bin/sh",
                        "echo ${EXEC_VAR_ONE}",
                        "echo ${EXEC_VAR_TWO}",
                        "echo ${1}"
                    ]
                script.write("\n".join(the_script).encode())
                script.close()
                os.chmod(script.name, 0o777)

                os.environ["EXEC_VAR_ONE"] = "{}://{}/{}/{}".format(SecretsManager.notation_prefix, one.uid, "field",
                                                                    "login")
                os.environ["EXEC_VAR_TWO"] = "{}://{}/{}/{}".format(SecretsManager.notation_prefix, one.uid,
                                                                    "custom_field", "password")

                runner = CliRunner()
                result = runner.invoke(cli, [
                    'exec', '--capture-output', '--inline',
                    script.name, "{}://{}/{}/{}[]".format(SecretsManager.notation_prefix, one.uid, "field", "password")
                ], catch_exceptions=False)
                print("-------------------")
                print(result.output)
                print("-------------------")
                self.assertIsNotNone(re.search('My Login 1', result.output, flags=re.MULTILINE),
                                     "did not find the login")
                self.assertIsNotNone(re.search('My Password 1', result.output, flags=re.MULTILINE),
                                     "did not find the custom field password")

                self.assertIsNotNone(re.search(r'PASS', result.output, flags=re.MULTILINE),
                                     "did not find the field password")

    def test_cmd_bad(self):

        # Log level set in this one, nothing below INFO should appear.
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.custom_field("password", "My Password 1")

        queue = mock.ResponseQueue(client=secrets_manager)
        # Profile init
        queue.add_response(res)

        # One for each var ... until we begin to cache.
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as \
                mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Make a temp shell script
            with tempfile.NamedTemporaryFile(delete=False) as script:
                self.delete_me.append(script.name)
                the_script = [
                    "#!/bin/sh",
                    "echo 'MOOT'"
                ]
                script.write("\n".join(the_script).encode())
                script.close()
                os.chmod(script.name, 0o777)

                # We should fail on this one
                os.environ["EXEC_MISSING_FIELD"] = "{}://{}/{}".format(SecretsManager.notation_prefix, one.uid,
                                                                       "field")
                # Should ignore this one
                os.environ["EXEC_BAD_ONE"] = "{}THIS IS BAD".format(SecretsManager.notation_prefix)

                # Should not even be processed
                os.environ["EXEC_NOT_ONE"] = "BLAH"

                runner = CliRunner()
                result = runner.invoke(cli, ['exec', '--capture-output', script.name], catch_exceptions=False)
                print("-------------------")
                print(result.output)
                print("-------------------")
                self.assertIsNotNone(re.search(f'MOOT', result.output, flags=re.MULTILINE), "did not find exception")


if __name__ == '__main__':
    unittest.main()
