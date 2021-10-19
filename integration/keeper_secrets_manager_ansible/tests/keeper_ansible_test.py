import unittest
from unittest.mock import patch
import os
import tempfile
import json

from keeper_secrets_manager_ansible import KeeperAnsible
from keeper_secrets_manager_ansible.__main__ import main
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
            config = json.dumps({
                "hostname": "dev.keepersecurity.com",
                "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=",
                "clientId": "Ae3589ktgynN6vvFtBwlsAbf0fHhXCcf7JqtKXK/3UCE"
                            "LujQuYuXvFFP08d2rb4aQ5Z4ozgD2yek9sjbWj7YoQ==",
                "clientKey": "KmsOqSq-aB0l7VraWHBHhMaZC2HYDDY5rJIgaP3qD7E",
                "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf54pIB7q_qV-B_2Zlw5NPZybvQzAHfZQFl4veRG"
                              "Z3YChRANCAASv7xdTLFfRuCIur0GUFIp1rPERmuBgtmUlSq72kYBwFO-NEbTjC9JUcZbQ73kDiGdvYwiuQqkKc7"
                              "q4aHc_zpzH"
            })
            temp_config.write(config)
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

        values = {
            "hostname": "dev.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=",
            "clientId": "Ae3589ktgynN6vvFtBwlsAbf0fHhXCcf7JqtKXK/3UCE"
                        "LujQuYuXvFFP08d2rb4aQ5Z4ozgD2yek9sjbWj7YoQ==",
            "client_key": "1zOuIXXkrrAaDioo6MX8yohRBC0otcBXF58Th5D0LOs",
            "private_key": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAPoRbTN0Nt7Go_nVMaSY8dgLFzvYmaH5_14JoyX-"
                           "z-ShRANCAATiHRnQxz4f3bAS8eFuhaaEDnbwZF3OLKbf7A_ZshyoPPqdKiEX-XU9dCTF3f0I-QPusqCzlUuAVu8J"
                           "UFNPvoJJ"
        }

        task_vars = {
            "keeper_verify_ssl_certs": False
        }
        for key in values:
            task_vars[KeeperAnsible.keeper_key(key)] = values[key]

        ka = KeeperAnsible(task_vars=task_vars)
        ka.client.get_secrets()
        mock_get_secrets.assert_called_once()

    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=get_secrets)
    def test_ansible_cli_init(self, mock_get_secrets):

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            main(["--keeper_token", "US:ii-oOUHxy0qHGHF97nd8APYZDVVR07LJj4U76Avcjno"])
        content = stdout.getvalue()
        self.assertRegex(content, r'Config file created', 'did not find expected text')
        with open("client-config.json", "r") as fh:
            config = json.load(fh)
            self.assertEqual("ii-oOUHxy0qHGHF97nd8APYZDVVR07LJj4U76Avcjno", config.get("clientKey"))
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
            os.environ["PSModulePath"] = "...\moodules:...\Modules:....\Modules"

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                main(["--config"])
            content = stdout.getvalue()
            self.assertRegex(content, r'\$env:ANSIBLE_ACTION_PLUGINS',
                             'did not find PS ANSIBLE_ACTION_PLUGINS')
            self.assertRegex(content, r'\$env:ANSIBLE_LOOKUP_PLUGINS',
                             'did not find PS ANSIBLE_LOOKUP_PLUGINS')

