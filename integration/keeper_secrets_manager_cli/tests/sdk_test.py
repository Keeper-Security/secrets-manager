import os
import unittest
from unittest.mock import patch
from click.testing import CliRunner
import tempfile
import json
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.__main__ import cli, KeeperCli
from integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.profile import Profile


class SdkTest(unittest.TestCase):

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

    def test_cmd(self):

        # Log level set in this one, nothing below INFO should appear.
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage({
            "hostname": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }), log_level="INFO")

        res_queue = mock.ResponseQueue(client=secrets_manager)

        res = mock.Response()
        one = res.add_record(title="My Record")

        # KEY ROTATION ERROR. error needs to be key.
        error_json = {
            "error": "key",
            "key_id": "6",

            # Need enough stuff in the message or a module will print to stdout a warning and messing up capturing
            # the stdout JSON
            "extra_stuff": "ABC123ZYX654"
        }

        # profile init
        res_queue.add_response(res)

        res_queue.add_response(mock.Response(content=json.dumps(error_json).encode(), status_code=403))
        res_queue.add_response(res)

        with patch('integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(
                token='rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ'
            )

            cli_obj = KeeperCli()
            self.assertEqual(SecretsManager.default_key_id,
                             cli_obj.config.get("serverpublickeyid"), "didn't get the correct key id")

            runner = CliRunner()
            result = runner.invoke(cli, ['secret', 'list', '--json'], catch_exceptions=False)
            record = json.loads(result.output)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")
            self.assertEqual(1, len(record), 'did not find 1 record')
            self.assertEqual(one.uid, record[0].get("uid"), "returned record isn't the one we wanted")

            cli_obj = KeeperCli()
            self.assertEqual("6", cli_obj.config.get("serverpublickeyid"), "didn't get the correct key id")


