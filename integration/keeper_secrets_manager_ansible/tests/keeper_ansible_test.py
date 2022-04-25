import unittest
from unittest.mock import patch
import os
import tempfile
import json

from keeper_secrets_manager_ansible import KeeperAnsible
from keeper_secrets_manager_ansible.__main__ import main
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.configkeys import ConfigKeys
import io
from contextlib import redirect_stdout


def get_secrets():
    return []


class KeeperAnsibleTest(unittest.TestCase):

    def setUp(self):

        # Add in addition Python libs. This includes the base
        # module for Keeper Ansible and the Keeper SDK.
        self.base_dir = os.path.dirname(os.path.realpath(__file__))

        # Make sure the a config file does not already exists.
        if os.path.exists("client-config.json") is True:
            os.unlink("client-config.json")

    def tearDown(self):
        # Clean up
        if os.path.exists("client-config.json") is True:
            os.unlink("client-config.json")

    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=get_secrets)
    def test_config_read_file_json_file(self, mock_get_secrets):

        """
        Create a JSON config file and load it using the Ansible variable where the config file name is
        specified.
        """

        with tempfile.NamedTemporaryFile("w", delete=False) as temp_config:
            temp_config.write(MockConfig.make_json())
            temp_config.seek(0)

            keeper_config_file_key = KeeperAnsible.keeper_key(KeeperAnsible.KEY_CONFIG_FILE_SUFFIX)

            ka = KeeperAnsible(
                task_vars={
                    keeper_config_file_key: temp_config.name,
                    "keeper_verify_ssl_certs": False
                }
            )
            ka.client.get_secrets()
            mock_get_secrets.assert_called_once()

    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=get_secrets)
    def test_config_in_ansible_task_vars(self, mock_get_secrets):

        values = MockConfig.make_config()

        task_vars = {
            "keeper_verify_ssl_certs": False,
            "keeper_client_id": values.get("clientId"),
            "keeper_app_key": values.get("appKey"),
            "keeper_private_key": values.get("privateKey"),
            "keeper_app_owner_public_key": values.get("appOwnerPublicKey")
        }

        ka = KeeperAnsible(task_vars=task_vars)
        ka.client.get_secrets()
        mock_get_secrets.assert_called_once()

        self.assertIsNotNone(ka.client.config.get(ConfigKeys.KEY_CLIENT_ID), "client id is none")
        self.assertEqual(values.get("clientId"), ka.client.config.get(ConfigKeys.KEY_CLIENT_ID),
                         "base64 client ids are not the same")
        self.assertIsNotNone(ka.client.config.get(ConfigKeys.KEY_APP_KEY), "app key is none")
        self.assertEqual(values.get("appKey"), ka.client.config.get(ConfigKeys.KEY_APP_KEY),
                         "base64 app key are not the same")
        self.assertIsNotNone(ka.client.config.get(ConfigKeys.KEY_PRIVATE_KEY), "private key is none")
        self.assertEqual(values.get("privateKey"), ka.client.config.get(ConfigKeys.KEY_PRIVATE_KEY),
                         "base64 private key are not the same")
        self.assertIsNotNone(ka.client.config.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY), "owner public key is none")
        self.assertEqual(values.get("appOwnerPublicKey"), ka.client.config.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY),
                         "base64 owner public key are not the same")

    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=get_secrets)
    def test_config_base_64(self, mock_get_secrets):

        values = MockConfig.make_config()
        base64_config = MockConfig.make_base64(config=values)

        task_vars = {
            "keeper_config": base64_config
        }

        ka = KeeperAnsible(task_vars=task_vars)
        ka.client.get_secrets()
        mock_get_secrets.assert_called_once()
        self.assertIsNotNone(ka.client.config.get(ConfigKeys.KEY_CLIENT_ID), "client id is none")
        self.assertEqual(values.get("clientId"), ka.client.config.get(ConfigKeys.KEY_CLIENT_ID),
                         "base64 client ids are not the same")
        self.assertIsNotNone(ka.client.config.get(ConfigKeys.KEY_APP_KEY), "app key is none")
        self.assertEqual(values.get("appKey"), ka.client.config.get(ConfigKeys.KEY_APP_KEY),
                         "base64 app key are not the same")
        self.assertIsNotNone(ka.client.config.get(ConfigKeys.KEY_PRIVATE_KEY), "private key is none")
        self.assertEqual(values.get("privateKey"), ka.client.config.get(ConfigKeys.KEY_PRIVATE_KEY),
                         "base64 private key are not the same")
        self.assertIsNotNone(ka.client.config.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY), "owner public key is none")
        self.assertEqual(values.get("appOwnerPublicKey"), ka.client.config.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY),
                         "base64 owner public key are not the same")

    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=get_secrets)
    def test_ansible_cli_init(self, _):

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            main(["--token", "US:MY_TOKEN"])
        content = stdout.getvalue()
        self.assertRegex(content, r'Config file created', 'did not find expected text')
        with open("client-config.json", "r") as fh:
            config = json.load(fh)
            self.assertEqual("MY_TOKEN", config.get("clientKey"))
            self.assertEqual("US", config.get("hostname"))
            fh.close()

    def test_ansible_cli_version(self):

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            main(["--version"])
        content = stdout.getvalue()
        self.assertRegex(content, r'ANSIBLE_LOOKUP_PLUGINS', 'did not find expected text')

    def test_ansible_cli_config(self):

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            main(["--config"])
        content = stdout.getvalue()
        self.assertRegex(content, r'ANSIBLE_ACTION_PLUGINS', 'did not find ANSIBLE_ACTION_PLUGINS')
        self.assertRegex(content, r'ANSIBLE_LOOKUP_PLUGINS', 'did not find ANSIBLE_LOOKUP_PLUGINS')

        # Test Windows. Future proofing since Ansible doesn't work directly on Windows. :/
        with patch('platform.system') as mock_system:
            mock_system.return_value = "Windows"

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                main(["--config"])
            content = stdout.getvalue()
            self.assertRegex(content, r'set ANSIBLE_ACTION_PLUGINS', 'did not find cmd ANSIBLE_ACTION_PLUGINS')
            self.assertRegex(content, r'set ANSIBLE_LOOKUP_PLUGINS', 'did not find cmd ANSIBLE_LOOKUP_PLUGINS')

        # Test Windows. Powershell!
        with patch('platform.system') as mock_system:
            mock_system.return_value = "Windows"

            # We are testing this on Linux. So the path separator is going to be : instead of ;
            os.environ["PSModulePath"] = r"...\modules:...\Modules:....\Modules"

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                main(["--config"])
            content = stdout.getvalue()
            self.assertRegex(content, r'\$env:ANSIBLE_ACTION_PLUGINS',
                             'did not find PS ANSIBLE_ACTION_PLUGINS')
            self.assertRegex(content, r'\$env:ANSIBLE_LOOKUP_PLUGINS',
                             'did not find PS ANSIBLE_LOOKUP_PLUGINS')

    def test_password_complexity(self):

        complexity = KeeperAnsible.password_complexity_translation(length=64)
        self.assertEqual(16, complexity.get("lowercase"), "lowercase is not 16")
        self.assertEqual(16, complexity.get("caps"), "uppercase is not 16")
        self.assertEqual(16, complexity.get("digits"), "digits is not 16")
        self.assertEqual(16, complexity.get("special"), "special_characters is not 16")

        complexity = KeeperAnsible.password_complexity_translation(length=64, allow_symbols=False)
        self.assertEqual(22, complexity.get("lowercase"), "lowercase is not 22")
        self.assertEqual(21, complexity.get("caps"), "uppercase is not 21")
        self.assertEqual(21, complexity.get("digits"), "digits is not 21")
        self.assertEqual(0, complexity.get("special"), "special_characters is not 0")
