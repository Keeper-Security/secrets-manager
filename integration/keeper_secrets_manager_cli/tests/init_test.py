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
from keeper_secrets_manager_core.mock import MockConfig
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

        mock_config = MockConfig.make_config()

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        # We kind of need to mock getting back the app key
        init_config = InMemoryKeyValueStorage()
        init_secrets_manager = SecretsManager(
            config=init_config,
            token="MY_TOKEN",
            hostname="US",
            verify_ssl_certs=False
        )
        # Add back the app key since it's deleted on the sm init. We don't get it unless we hit the server.
        init_config.set(ConfigKeys.KEY_APP_KEY, mock_config.get("appKey"))

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

                    token = "US:MY_TOKEN"
                    runner = CliRunner()
                    result = runner.invoke(cli, ['init ', 'default', token], catch_exceptions=False)
                    self.assertEqual(0, result.exit_code, "did not get a success for default init")

                    json_config = base64.b64decode(result.output.encode())
                    config = json.loads(json_config.decode())
                    self.assertIsNotNone(config.get("clientId"), "client id is missing")
                    self.assertIsNotNone(config.get("privateKey"), "private key is missing")
                    self.assertIsNotNone(config.get("appKey"), "app key is missing")
                    self.assertIsNotNone(config.get("hostname"), "hostname is missing")
                    self.assertEqual("keepersecurity.com", config.get("hostname"), "hostname is not correct")
                    self.assertEqual(mock_config.get("appKey"), config.get("appKey"),
                                     "app key is not correct")

        # JSON OUTPUT
        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = secrets_manager
            with patch('keeper_secrets_manager_cli.init.Init.get_client') as mock_init_client:
                mock_init_client.return_value = init_secrets_manager
                with patch('keeper_secrets_manager_cli.init.Init.init_config') as mock_init_config:
                    mock_init_config.return_value = init_config

                    token = "US:MY_TOKEN"
                    runner = CliRunner()
                    result = runner.invoke(cli, ['init ', 'default', token, '--plain'], catch_exceptions=False)
                    self.assertEqual(0, result.exit_code, "did not get a success for default init")

                    config = json.loads(result.output)
                    self.assertIsNotNone(config.get("clientId"), "client id is missing")
                    self.assertIsNotNone(config.get("privateKey"), "private key is missing")
                    self.assertIsNotNone(config.get("appKey"), "app key is missing")
                    self.assertIsNotNone(config.get("hostname"), "hostname is missing")
                    self.assertEqual("keepersecurity.com", config.get("hostname"), "hostname is not correct")
                    self.assertEqual(mock_config.get("appKey"), config.get("appKey"),
                                     "app key is not correct")

    def test_k8s(self):

        """ Test initializing the profile
        """

        mock_config = MockConfig.make_config()

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        # We kind of need to mock getting back the app key
        init_config = InMemoryKeyValueStorage()
        init_secrets_manager = SecretsManager(
            config=init_config,
            token="MY_TOKEN",
            hostname="US",
            verify_ssl_certs=False
        )
        init_config.set(ConfigKeys.KEY_APP_KEY, mock_config.get("appKey"))

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

                    token = "US:MY_TOKEN"
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
                    self.assertEqual("keepersecurity.com", config.get("hostname"), "hostname is not correct")
                    self.assertEqual(mock_config.get("appKey"), config.get("appKey"),
                                     "app key is not correct")
