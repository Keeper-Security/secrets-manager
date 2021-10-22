import base64
import os
import unittest
from unittest.mock import patch

import yaml
from click.testing import CliRunner
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_cli.__main__ import cli
import tempfile
import json
from io import StringIO


class InitTest(unittest.TestCase):

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

    def test_default(self):

        """ Test initializing the profile
        """

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage({
            "hostname": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=",
            "clientId": "Ae3589ktgynN6vvFtBwlsAbf0fHhXCcf7JqtKXK/3UCE"
                        "LujQuYuXvFFP08d2rb4aQ5Z4ozgD2yek9sjbWj7YoQ==",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        # We kind of need to mock getting back the app key
        init_config = InMemoryKeyValueStorage()
        init_secrets_manager = SecretsManager(
            config=init_config,
            token="JG49ehxg_GW9FZkgtDcXUZTOKw-SArPuBCN89vDvztc",
            hostname="US",
            verify_ssl_certs=False
        )
        init_config.set(ConfigKeys.KEY_APP_KEY, "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=")

        res = mock.Response()
        res.add_record(title="My Record 1")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        init_queue = mock.ResponseQueue(client=init_secrets_manager)
        init_queue.add_response(res)
        init_queue.add_response(res)

        # BASE 64 ENCODED
        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager
            with patch('keeper_secrets_manager_cli.init.Init.get_client') as mock_init_client:
                mock_init_client.return_value = init_secrets_manager
                with patch('keeper_secrets_manager_cli.init.Init.init_config') as mock_init_config:
                    mock_init_config.return_value = init_config

                    token = "US:JG49ehxg_GW9FZkgtDcXUZTOKw-SArPuBCN89vDvztc"
                    runner = CliRunner()
                    result = runner.invoke(cli, ['init ', 'default', token], catch_exceptions=False)
                    self.assertEqual(0, result.exit_code, "did not get a success for default init")

                    json_config = base64.b64decode(result.output.encode())
                    config = json.loads(json_config.decode())
                    self.assertIsNotNone(config.get("clientId"), "client id is missing")
                    self.assertIsNotNone(config.get("privateKey"), "private key is missing")
                    self.assertIsNotNone(config.get("appKey"), "app key is missing")
                    self.assertIsNotNone(config.get("hostname"), "hostname is missing")
                    self.assertEqual("US", config.get("hostname"), "hostname is not correct")
                    self.assertEqual("9vVajcvJTGsa2Opc/jvhEiJLRKHtg2Rm4PAtUoP3URw=", config.get("appKey"),
                                     "app key is not correct")

        # JSON OUTPUT
        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager
            with patch('keeper_secrets_manager_cli.init.Init.get_client') as mock_init_client:
                mock_init_client.return_value = init_secrets_manager
                with patch('keeper_secrets_manager_cli.init.Init.init_config') as mock_init_config:
                    mock_init_config.return_value = init_config

                    token = "US:JG49ehxg_GW9FZkgtDcXUZTOKw-SArPuBCN89vDvztc"
                    runner = CliRunner()
                    result = runner.invoke(cli, ['init ', 'default', token, '--plain'], catch_exceptions=False)
                    self.assertEqual(0, result.exit_code, "did not get a success for default init")

                    config = json.loads(result.output)
                    self.assertIsNotNone(config.get("clientId"), "client id is missing")
                    self.assertIsNotNone(config.get("privateKey"), "private key is missing")
                    self.assertIsNotNone(config.get("appKey"), "app key is missing")
                    self.assertIsNotNone(config.get("hostname"), "hostname is missing")
                    self.assertEqual("US", config.get("hostname"), "hostname is not correct")
                    self.assertEqual("9vVajcvJTGsa2Opc/jvhEiJLRKHtg2Rm4PAtUoP3URw=", config.get("appKey"),
                                     "app key is not correct")

    def test_k8s(self):

        """ Test initializing the profile
        """

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage({
            "hostname": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=",
            "clientId": "Ae3589ktgynN6vvFtBwlsAbf0fHhXCcf7JqtKXK/3UCE"
                        "LujQuYuXvFFP08d2rb4aQ5Z4ozgD2yek9sjbWj7YoQ==",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        # We kind of need to mock getting back the app key
        init_config = InMemoryKeyValueStorage()
        init_secrets_manager = SecretsManager(
            config=init_config,
            token="JG49ehxg_GW9FZkgtDcXUZTOKw-SArPuBCN89vDvztc",
            hostname="US",
            verify_ssl_certs=False
        )
        init_config.set(ConfigKeys.KEY_APP_KEY, "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=")

        res = mock.Response()
        res.add_record(title="My Record 1")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)

        init_queue = mock.ResponseQueue(client=init_secrets_manager)
        init_queue.add_response(res)
        init_queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager
            with patch('keeper_secrets_manager_cli.init.Init.get_client') as mock_init_client:
                mock_init_client.return_value = init_secrets_manager
                with patch('keeper_secrets_manager_cli.init.Init.init_config') as mock_init_config:
                    mock_init_config.return_value = init_config

                    token = "US:JG49ehxg_GW9FZkgtDcXUZTOKw-SArPuBCN89vDvztc"
                    runner = CliRunner()
                    result = runner.invoke(cli, [
                        'init ', 'k8s', token,
                        '--name', 'mine',
                        '--namespace', 'my_ns'
                    ], catch_exceptions=False)
                    self.assertEqual(0, result.exit_code, "did not get a success for default init")

                    fh = StringIO(result.output)

                    # This is horrible. CLI can't use yaml
                    script = yaml.load(fh, yaml.Loader)

                    json_config = base64.b64decode(script['data']['config'])
                    config = json.loads(json_config.decode())

                    self.assertEqual("v1", script.get("apiVersion"), "missing the api version")
                    self.assertIsNotNone(script.get("data"), "missing the data")
                    self.assertEqual("Secret", script.get("kind"), "missing the kind")
                    self.assertIsNotNone(script.get("metadata"), "missing the meta data")
                    self.assertEqual("Opaque", script.get("type"), "missing the kind")

                    metadata = script.get("metadata")
                    self.assertEqual("mine", metadata.get("name"), "missing the kind")
                    self.assertEqual("my_ns", metadata.get("namespace"), "missing the kind")

                    self.assertIsNotNone(config.get("clientId"), "client id is missing")
                    self.assertIsNotNone(config.get("privateKey"), "private key is missing")
                    self.assertIsNotNone(config.get("appKey"), "app key is missing")
                    self.assertIsNotNone(config.get("hostname"), "hostname is missing")
                    self.assertEqual("US", config.get("hostname"), "hostname is not correct")
                    self.assertEqual("9vVajcvJTGsa2Opc/jvhEiJLRKHtg2Rm4PAtUoP3URw=", config.get("appKey"),
                                     "app key is not correct")


