import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from keeper_secrets_manager_core import mock

from keeper_secrets_manager_ansible import KeeperAnsible


class KeeperBooleanVariableTest(unittest.TestCase):
    """A boolean variable from -e key=value or an INI inventory is text. "false" must not turn an option on."""

    def setUp(self):
        from ansible.errors import AnsibleError
        error_patch = patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError)
        error_patch.start()
        self.addCleanup(error_patch.stop)
        self.action = SimpleNamespace(_task=SimpleNamespace(args={}, check_mode=False))
        values = mock.MockConfig.make_config()
        self.config_vars = {
            "keeper_client_id": values["clientId"],
            "keeper_private_key": values["privateKey"],
            "keeper_app_key": values["appKey"],
            "keeper_hostname": values["hostname"],
        }

    def _verify_ssl_certs(self, value):
        task_vars = dict(self.config_vars, keeper_config_file="/nonexistent/keeper.json")
        if value is not None:
            task_vars["keeper_verify_ssl_certs_skip"] = value
        with patch.dict(os.environ), patch.object(KeeperAnsible, "get_client") as get_client:
            os.environ.pop("KSM_SKIP_VERIFY", None)
            KeeperAnsible(task_vars=task_vars, action_module=self.action)
        return get_client.call_args.kwargs["verify_ssl_certs"]

    def test_verify_ssl_certs_skip_reads_text_values(self):
        for value in ("false", "False", "no", "0", "off", False, 0, None):
            with self.subTest(value=value):
                self.assertIs(self._verify_ssl_certs(value), True)
        for value in ("true", "True", "yes", "1", "on", True, 1):
            with self.subTest(value=value):
                self.assertIs(self._verify_ssl_certs(value), False)

    def test_verify_ssl_certs_skip_rejects_a_value_that_is_not_a_boolean(self):
        with self.assertRaisesRegex(Exception, "keeper_verify_ssl_certs_skip variable must be true or false, not "
                                               "'sometimes'"):
            self._verify_ssl_certs("sometimes")

    def test_force_config_write_reads_text_values(self):
        for value, written in (("false", False), ("no", False), (False, False), ("true", True), (True, True)):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory, \
                    patch.object(KeeperAnsible, "get_client"):
                path = Path(directory) / "keeper.json"
                KeeperAnsible(task_vars=dict(self.config_vars, keeper_config_file=str(path),
                                             keeper_force_config_write=value), action_module=self.action)
                self.assertIs(path.exists(), written)

    def test_turned_off_certificate_verification_is_shown(self):
        for verify, warned in ((False, True), (True, False)):
            with self.subTest(verify=verify), \
                    patch.object(KeeperAnsible, "get_client", return_value=SimpleNamespace(verify_ssl_certs=verify)), \
                    patch("keeper_secrets_manager_ansible.display.warning") as warning:
                KeeperAnsible(task_vars=dict(self.config_vars, keeper_config_file="/nonexistent/keeper.json"),
                              action_module=self.action)
                messages = [str(call.args[0]) for call in warning.call_args_list]
                self.assertIs(any("does not verify the TLS certificate" in m for m in messages), warned)
