import os
import unittest
from unittest.mock import patch
from click.testing import CliRunner
import tempfile
import re
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.__main__ import cli
from integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.profile import Profile


class ExecTest(unittest.TestCase):

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

    def test_cmd(self):

        # Log level set in this one, nothing below INFO should appear.
        commander = SecretsManager(config=InMemoryKeyValueStorage({
            "server": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }), log_level="INFO")

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.custom_field("password", "My Password 1")

        queue = mock.ResponseQueue(client=commander)
        # Profile init
        queue.add_response(res)

        # One for each var ... until we begin to cache.
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.KeeperCli.get_client') as \
                mock_client:
            mock_client.return_value = commander

            Profile.init(
                client_key='rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ'
            )

            # Make a temp shell script
            with tempfile.NamedTemporaryFile() as script:
                the_script = [
                    "#!/bin/sh",
                    "echo ${VAR_ONE}",
                    "echo ${VAR_TWO}",
                    "echo ${NOT_ONE}"
                ]
                script.write("\n".join(the_script).encode())
                script.seek(0)
                os.chmod(script.name, 0o777)

                os.environ["VAR_ONE"] = "{}://{}/{}/{}".format(SecretsManager.notation_prefix, one.uid, "field", "login")
                os.environ["VAR_TWO"] = "{}://{}/{}/{}".format(SecretsManager.notation_prefix, one.uid, "custom_field",
                                                               "password")
                os.environ["NOT_ONE"] = "BLAH"

                runner = CliRunner()
                result = runner.invoke(cli, ['exec', '--capture-output', script.name], catch_exceptions=False)
                self.assertIsNotNone(re.search('My Login 1', result.output, flags=re.MULTILINE),
                                     "did not find the login")
                self.assertIsNotNone(re.search('My Password 1', result.output, flags=re.MULTILINE),
                                     "did not find the password")
                self.assertIsNotNone(re.search('BLAH', result.output, flags=re.MULTILINE),
                                     "did not find the not one")
                script.close()

    def test_cmd_inline(self):

        # Log level set in this one, nothing below INFO should appear.
        commander = SecretsManager(config=InMemoryKeyValueStorage({
            "server": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }), log_level="INFO")

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "PASS")
        one.custom_field("password", "My Password 1")

        queue = mock.ResponseQueue(client=commander)
        # Profile init
        queue.add_response(res)

        # One for each var ... until we begin to cache.
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = commander

            Profile.init(
                client_key='rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ'
            )

            # Make a temp shell script
            with tempfile.NamedTemporaryFile() as script:
                the_script = [
                    "#!/bin/sh",
                    "echo ${VAR_ONE}",
                    "echo ${VAR_TWO}",
                    "echo ${1}"
                ]
                script.write("\n".join(the_script).encode())
                script.seek(0)
                os.chmod(script.name, 0o777)

                os.environ["VAR_ONE"] = "{}://{}/{}/{}".format(SecretsManager.notation_prefix, one.uid, "field", "login")
                os.environ["VAR_TWO"] = "{}://{}/{}/{}".format(SecretsManager.notation_prefix, one.uid, "custom_field",
                                                               "password")

                runner = CliRunner()
                result = runner.invoke(cli, [
                    'exec', '--capture-output', '--inline',
                    script.name, "{}://{}/{}/{}[]".format(SecretsManager.notation_prefix, one.uid, "field", "password")
                ], catch_exceptions=False)
                self.assertIsNotNone(re.search('My Login 1', result.output, flags=re.MULTILINE),
                                     "did not find the login")
                self.assertIsNotNone(re.search('My Password 1', result.output, flags=re.MULTILINE),
                                     "did not find the custom field password")

                # For coverage we request the full array value for this one, hence ["PASS"]
                self.assertIsNotNone(re.search('\["PASS"\]', result.output, flags=re.MULTILINE),
                                     "did not find the field password")
                script.close()


if __name__ == '__main__':
    unittest.main()
