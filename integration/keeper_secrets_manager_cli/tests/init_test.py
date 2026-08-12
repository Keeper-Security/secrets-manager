import base64
import os
import unittest
from contextlib import contextmanager
from unittest.mock import patch
import yaml
from conftest import CliRunner
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
                    script = yaml.safe_load(fh)

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

    def test_k8s_name_injection_is_neutralized(self):

        """A newline in --namespace cannot inject manifest content.

        --name is rejected outright by RFC 1123 validation, so only --namespace
        still reaches the serializer with arbitrary content.
        """

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

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
                    malicious_ns = "evil\nns-injected: pwned"
                    runner = CliRunner()
                    result = runner.invoke(cli, [
                        'init ', 'k8s', token,
                        '--name', 'mine',
                        '--namespace', malicious_ns,
                        '--immutable'
                    ], catch_exceptions=False)
                    self.assertEqual(0, result.exit_code, "k8s init did not succeed")

                    script = yaml.safe_load(StringIO(result.output))
                    # The injected key must not appear as manifest content, neither at
                    # the top level nor inside metadata.
                    self.assertNotIn("ns-injected", script)
                    self.assertEqual({"name", "namespace"}, set(script["metadata"]))
                    # The malicious value is preserved verbatim as a single scalar.
                    self.assertEqual(malicious_ns, script["metadata"]["namespace"])
                    self.assertEqual("Secret", script.get("kind"))
                    self.assertIs(script.get("immutable"), True)

    @contextmanager
    def _patched_cli(self):

        """Patch the client entry points so the CLI never hits the network."""

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

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
        for client in (secrets_manager, init_secrets_manager):
            queue = mock.ResponseQueue(client=client)
            queue.add_response(res)
            queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client', return_value=secrets_manager), \
                patch('keeper_secrets_manager_cli.init.Init.get_client', return_value=init_secrets_manager), \
                patch('keeper_secrets_manager_cli.init.Init.init_config', return_value=init_config):
            yield

    def test_k8s_apply_rejects_dash_name(self):

        """A --name that kubectl would read as one of its own flags is rejected."""

        with self._patched_cli():
            runner = CliRunner()
            result = runner.invoke(cli, [
                'init ', 'k8s', '--apply',
                '--name', '--kubeconfig=/tmp/x',
                'FAKE_TOKEN'
            ], catch_exceptions=False)

        self.assertNotEqual(0, result.exit_code, "a flag-shaped name was accepted")
        self.assertIn("must consist of lowercase alphanumeric", result.output)

    def test_k8s_apply_valid_name(self):

        """A valid --name reaches kubectl as the NAME positional, not as a flag."""

        with self._patched_cli():
            with patch('keeper_secrets_manager_cli.init.subprocess.run') as mock_run:
                runner = CliRunner()
                result = runner.invoke(cli, [
                    'init ', 'k8s', '--apply',
                    '--name', 'my-secret',
                    'FAKE_TOKEN'
                ], catch_exceptions=False)

        self.assertEqual(0, result.exit_code, result.output)
        mock_run.assert_called_once()

        argv = mock_run.call_args[0][0]
        self.assertEqual(["kubectl", "create", "secret", "generic"], argv[:4])
        # kubectl reads NAME as the only positional, so it has to be its own argv
        # element and it must not be flag-shaped.
        self.assertEqual("my-secret", argv[4])
        self.assertFalse(argv[4].startswith("-"))

    def test_k8s_rejects_invalid_names(self):

        """RFC 1123 validation covers the manifest branch too, not just --apply."""

        for invalid_name, desc in [
            ('MySecret', 'uppercase'),
            ('-leading-dash', 'leading dash'),
            ('trailing-dash-', 'trailing dash'),
            ('evil\ninjected: pwned', 'newline'),
            ('under_score', 'underscore'),
            ('a' * 254, '254 characters'),
        ]:
            with self._patched_cli():
                runner = CliRunner()
                result = runner.invoke(cli, [
                    'init ', 'k8s',
                    '--name', invalid_name,
                    'FAKE_TOKEN'
                ], catch_exceptions=False)

            self.assertNotEqual(0, result.exit_code, "expected failure for {}".format(desc))
            self.assertIn("must consist of lowercase alphanumeric", result.output,
                          "expected validation error for {}".format(desc))
