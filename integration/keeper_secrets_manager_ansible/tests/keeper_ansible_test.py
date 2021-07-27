import unittest
from unittest.mock import patch
import os
import sys
import tempfile
import json

from keeper_secrets_manager_ansible import KeeperAnsible


def mocked_commander_get_secrets():
    return []


class KeeperAnsibleTest(unittest.TestCase):

    def setUp(self):

        # Add in addition Python libs. This includes the base
        # module for Keeper Ansible and the Keeper SDK.
        self.base_dir = os.path.dirname(os.path.realpath(__file__))
        sys.path.append(os.path.join(self.base_dir, "..", "modules"))
        sys.path.append(os.path.join(self.base_dir, "..", "..", "..", "..", "sdk", "python", "core"))

    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=mocked_commander_get_secrets)
    def test_config_read_file_json_file(self, mock_get_secrets):

        """
        Create a JSON config file and load it using the Ansible variable where the config file name is
        specified.
        """

        with tempfile.NamedTemporaryFile("w", delete=False) as temp_config:
            config = json.dumps({
                "hostname": "dev.keepersecurity.com",
                "appKey": "4I57jIjbn2OCNwCFzyGHek0YFfhdh2y9TLTncOwujmM",
                "clientId": "yccmFNJ9X6hKZerHWPipakDWHYCgCjjP86zwKM9N94Y",
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

    @patch("keeper_secrets_manager_core.core.SecretsManager.get_secrets", side_effect=mocked_commander_get_secrets)
    def test_config_in_ansible_task_vars(self, mock_get_secrets):

        values = {
            "hostname": "dev.keepersecurity.com",
            "app_key": "hDlYsYMPNJMhJb7d_Ca4u1yl5RSUzCvuIsFx32h7t04",
            "client_id": "PrF-9pxKIiLzngZb31GpimYXMhQgO9w1jO8PwfBD554",
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
