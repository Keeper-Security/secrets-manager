import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.core import KSMCache

from keeper_secrets_manager_ansible import KeeperAnsible
from .ansible_test_framework import AnsibleTestFramework


class KeeperCacheDirTest(unittest.TestCase):
    """keeper_cache_dir of one task must not become the DR cache directory of later tasks."""

    def setUp(self):
        from ansible.errors import AnsibleError
        for target, value in (("keeper_secrets_manager_ansible.AnsibleError", AnsibleError),):
            started = patch(target, value)
            started.start()
            self.addCleanup(started.stop)
        for started in (patch.object(KeeperAnsible, "_plugin_cache_dir", None),
                        patch.object(KSMCache, "kms_cache_file_name", KSMCache.kms_cache_file_name),
                        patch.dict(os.environ), patch.object(KeeperAnsible, "get_client")):
            started.start()
            self.addCleanup(started.stop)
        os.environ.pop("KSM_CACHE_DIR", None)
        self.action = SimpleNamespace(_task=SimpleNamespace(args={}, check_mode=False))
        self.config = mock.MockConfig.make_base64()

    def _keeper(self, cache_dir=None):
        task_vars = {"keeper_config": self.config, "keeper_config_file": "/nonexistent/keeper.json",
                     "keeper_use_cache": True}
        if cache_dir is not None:
            task_vars["keeper_cache_dir"] = cache_dir
        return KeeperAnsible(task_vars=task_vars, action_module=self.action)

    def test_a_later_task_uses_its_own_cache_dir(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            # The first task can be a lookup in the controller. Its value reaches every later worker.
            self._keeper(first)
            self.assertEqual(os.environ["KSM_CACHE_DIR"], first)
            self._keeper(second)
            self.assertEqual(os.environ["KSM_CACHE_DIR"], second)
            self.assertEqual(KeeperAnsible._cache_file_path(), os.path.join(second, "ksm_cache.bin"))
            # A task with the cache but without keeper_cache_dir uses the default, not the directory of a task before.
            self._keeper()
            self.assertNotIn("KSM_CACHE_DIR", os.environ)
            self.assertEqual(KeeperAnsible._cache_file_path(), "ksm_cache.bin")

    def test_a_cache_dir_that_the_user_sets_wins(self):
        with tempfile.TemporaryDirectory() as user_dir, tempfile.TemporaryDirectory() as task_dir:
            os.environ["KSM_CACHE_DIR"] = user_dir
            self._keeper(task_dir)
            self.assertEqual(os.environ["KSM_CACHE_DIR"], user_dir)
            self._keeper()
            self.assertEqual(os.environ["KSM_CACHE_DIR"], user_dir)
            self.assertEqual(Path(KeeperAnsible._cache_file_path()).parent, Path(user_dir))


class KeeperCacheRecord(unittest.TestCase):

    def test_keeper_cache_records(self):

        mock_response = mock.Response()
        uids = []
        titles = []
        record_10_uid = None
        for index in range(0, 100):

            title = f"Record {index}"
            record = mock_response.add_record(title=title, record_type="login")
            record.field("login", f"MYLOGIN_{index}")
            record.field("password", f"MYPASSWORD_{index}")

            if index == 10:
                record_10_uid = record.uid

            if index < 50:
                uids.append(record.uid)
            else:
                titles.append(title)

        with tempfile.TemporaryDirectory() as temp_dir:
            a = AnsibleTestFramework(
                playbook="keeper_cache_records.yml",
                vars={
                    "tmp_dir": temp_dir,
                    "uids": uids,
                    "titles": titles,
                    "record_10_uid": record_10_uid
                },
                mock_responses=[mock_response]
            )
            result, out, err = a.run()
            self.assertEqual(result["ok"], 7, "7 things didn't happen")
            self.assertEqual(result["failed"], 0, "failed was not 0")
            self.assertEqual(result["changed"], 0, "0 things didn't change")
            assert "MYPASSWORD_10" in out
            assert "MYPASSWORD_75" in out
