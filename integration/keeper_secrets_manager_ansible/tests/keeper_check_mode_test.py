import ast
import base64
import importlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import yaml
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.core import KSMCache
from keeper_secrets_manager_core.dto.dtos import KeeperFolder
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_helper.record import Record

import keeper_secrets_manager_ansible.plugins
from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFieldType
from .ansible_test_framework import AnsibleTestFramework


SHARED_UID = "SHARED_FOLDER_UID"
SUBFOLDER_UID = "SUBFOLDER_UID"
CHECK_MODE_POST = "KeeperAnsible._check_mode_caching_post_function"
NORMAL_POST = "KeeperAnsible._caching_post_function"
PLUGIN_DIR = Path(keeper_secrets_manager_ansible.plugins.__file__).parent
PLAYBOOK_DIR = Path(__file__).parent / "ansible_example" / "playbooks"


def _folders(existing=False):
    folders = [
        KeeperFolder(b"k" * 32, SHARED_UID, "", "Shared Folder"),
        KeeperFolder(b"s" * 32, SUBFOLDER_UID, SHARED_UID, "Subfolder"),
    ]
    if existing:
        folders.append(KeeperFolder(b"f" * 32, "EXISTING_FOLDER_UID", SUBFOLDER_UID, "New Folder"))
    return folders


def _no_network(url, *args, **kwargs):
    raise AssertionError("A test sent a request to the Keeper server: {}".format(url.rsplit("/", 1)[-1]))


def _keeper():
    keeper = object.__new__(KeeperAnsible)
    keeper.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()))
    # MockConfig picks a random hostname. A request that a test does not patch must fail here, not reach the network.
    keeper.client.post_function = _no_network
    keeper.client.custom_post_function = None
    return keeper


def _token():
    # A one-time token has the form of a URL-safe base64 key. This one is random and unused.
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


def _unload_ansible():
    # A test that imports a plugin also loads the Ansible plugin loader with its default paths. The playbook tests
    # need a fresh loader with the Keeper paths, as AnsibleTestFramework does after each run.
    for module in list(sys.modules):
        if module.startswith("ansible"):
            sys.modules.pop(module, None)


def _task_context_available():
    try:
        return importlib.util.find_spec("ansible._internal._task") is not None
    except ImportError:
        return False
    finally:
        _unload_ansible()


def _read_lines(path):
    return path.read_text().splitlines() if path.exists() else []


def _read_clients(path):
    return [json.loads(line) for line in _read_lines(path)]


def _confirmed_delete(record_uids):
    # A real server confirms each delete with an "ok" status. keeper_remove fails without it.
    return [{"recordUid": uid, "responseCode": "ok"} for uid in record_uids]


class KeeperCheckModeConfigTest(unittest.TestCase):

    def setUp(self):
        from ansible.errors import AnsibleError
        error_patch = patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError)
        error_patch.start()
        self.addCleanup(error_patch.stop)
        self.action = SimpleNamespace(_task=SimpleNamespace(args={}, check_mode=True))

    def test_existing_config_is_loaded_in_memory_and_never_rewritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keeper.json"
            values = mock.MockConfig.make_config()
            values.pop("serverPublicKeyId", None)
            original = json.dumps(values).encode()
            path.write_bytes(original)
            before = path.stat().st_mtime_ns
            keeper = KeeperAnsible(
                task_vars={"keeper_config_file": str(path)},
                action_module=self.action,
            )

            self.assertIsInstance(keeper.client.config, InMemoryKeyValueStorage)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(path.stat().st_mtime_ns, before)
            self.assertIsNotNone(keeper.client.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID))

    def test_check_mode_config_file_gets_the_sdk_permission_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keeper.json"
            path.write_text(json.dumps(mock.MockConfig.make_config()))
            with patch("keeper_secrets_manager_ansible.check_config_mode") as check_config_mode:
                KeeperAnsible(task_vars={"keeper_config_file": str(path)}, action_module=self.action)
            check_config_mode.assert_called_once_with(str(path))

    def test_empty_config_file_reports_the_missing_keys(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop("KSM_TOKEN", None)
            path = Path(directory) / "keeper.json"
            path.write_text("")
            with patch.object(KeeperAnsible, "get_client") as get_client:
                with self.assertRaisesRegex(Exception, "The configuration from the file .*keeper.json has no "
                                                       r"clientId \(keeper_client_id\), privateKey"):
                    KeeperAnsible(task_vars={"keeper_config_file": str(path)}, action_module=self.action)
                get_client.assert_not_called()
            self.assertEqual(path.read_text(), "")

    def test_config_file_must_hold_a_json_object(self):
        for text, message in (
            (json.dumps(mock.MockConfig.make_base64()), "does not contain a JSON object"),
            ('{"clientId": ', "is not valid JSON"),
        ):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "keeper.json"
                path.write_text(text)
                with patch.object(KeeperAnsible, "get_client") as get_client:
                    with self.assertRaisesRegex(Exception, message):
                        KeeperAnsible(task_vars={"keeper_config_file": str(path)}, action_module=self.action)
                    get_client.assert_not_called()
                self.assertEqual(path.read_text(), text)

    def test_force_config_write_does_not_create_a_file_in_check_mode(self):
        values = mock.MockConfig.make_config()
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop("KSM_TOKEN", None)
            path = Path(directory) / "keeper.json"
            keeper = KeeperAnsible(
                task_vars={
                    "keeper_config_file": str(path),
                    "keeper_force_config_write": True,
                    "keeper_client_id": values["clientId"],
                    "keeper_private_key": values["privateKey"],
                    "keeper_app_key": values["appKey"],
                    "keeper_hostname": values["hostname"],
                },
                action_module=self.action,
            )
            self.assertIsInstance(keeper.client.config, InMemoryKeyValueStorage)
            self.assertFalse(path.exists())

    def test_unbound_token_does_not_construct_a_client_or_create_a_file(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop("KSM_TOKEN", None)
            path = Path(directory) / "keeper.json"
            with patch.object(KeeperAnsible, "get_client") as get_client:
                with self.assertRaisesRegex(Exception, "keeper_\\* variables has no .*It has a one-time token, and "
                                                       "check mode cannot redeem it"):
                    KeeperAnsible(
                        task_vars={"keeper_config_file": str(path), "keeper_token": "UNUSED_TOKEN"},
                        action_module=self.action,
                    )
                get_client.assert_not_called()
            self.assertFalse(path.exists())

    def test_environment_token_does_not_construct_a_client_or_create_a_file(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"KSM_TOKEN": "UNUSED_TOKEN"}):
            path = Path(directory) / "keeper.json"
            with patch.object(KeeperAnsible, "get_client") as get_client:
                with self.assertRaisesRegex(Exception, "It has a one-time token, and check mode cannot redeem it"):
                    KeeperAnsible(
                        task_vars={"keeper_config_file": str(path)},
                        action_module=self.action,
                    )
                get_client.assert_not_called()
            self.assertFalse(path.exists())

    def test_incomplete_file_and_base64_configs_are_rejected_before_client_initialization(self):
        for missing_key, variable in (("clientId", "keeper_client_id"), ("privateKey", "keeper_private_key"),
                                      ("appKey", "keeper_app_key")):
            for source in ("file", "base64"):
                with self.subTest(missing_key=missing_key, source=source), patch.dict(os.environ):
                    os.environ.pop("KSM_TOKEN", None)
                    values = mock.MockConfig.make_config()
                    # MockConfig keeps the token that bound it. A bound configuration from keeper_init has none.
                    values.pop("clientKey", None)
                    values.pop(missing_key)
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / "keeper.json"
                        original = json.dumps(values).encode()
                        if source == "file":
                            path.write_bytes(original)
                            task_vars = {"keeper_config_file": str(path)}
                            source_text = "the file {}".format(path)
                        else:
                            task_vars = {
                                "keeper_config_file": str(path),
                                "keeper_config": mock.MockConfig.make_base64(config=values),
                            }
                            source_text = "the keeper_config variable"
                        with patch.object(KeeperAnsible, "get_client") as get_client:
                            with self.assertRaises(Exception) as context:
                                KeeperAnsible(task_vars=task_vars, action_module=self.action)
                            get_client.assert_not_called()
                        message = str(context.exception)
                        self.assertIn("initialized Keeper configuration", message)
                        self.assertIn("The configuration from {} has no {} ({}).".format(
                            source_text, missing_key, variable), message)
                        # Nothing in these configurations is a one-time token.
                        self.assertNotIn("one-time token", message)
                        if source == "file":
                            self.assertEqual(path.read_bytes(), original)
                        else:
                            self.assertFalse(path.exists())

    def test_modules_that_never_contact_the_vault_accept_an_unbound_token(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop("KSM_TOKEN", None)
            path = Path(directory) / "keeper.json"
            with patch.object(KeeperAnsible, "get_client") as get_client:
                KeeperAnsible(task_vars={"keeper_config_file": str(path), "keeper_token": _token()},
                              action_module=self.action, requires_vault=False)
            self.assertIsInstance(get_client.call_args.kwargs["config"], InMemoryKeyValueStorage)
            self.assertFalse(path.exists())

    def test_lookup_check_mode_follows_the_check_option(self):
        from keeper_secrets_manager_ansible.plugins.lookup.keeper import LookupModule
        self.addCleanup(_unload_ansible)
        # Outside a task, the lookup can only read ansible_check_mode.
        self.assertTrue(LookupModule._check_mode({"ansible_check_mode": True}))
        self.assertFalse(LookupModule._check_mode({"ansible_check_mode": False}))
        self.assertFalse(LookupModule._check_mode({}))
        self.assertFalse(LookupModule._check_mode(None))

    def test_lookup_check_mode_prefers_the_task_context(self):
        try:
            from ansible._internal import _task
        except ImportError:
            self.skipTest("ansible-core before 2.19 has no task context")
        from keeper_secrets_manager_ansible.plugins.lookup.keeper import LookupModule
        self.addCleanup(_unload_ansible)
        for task_check_mode, option in ((True, False), (False, True)):
            with self.subTest(task_check_mode=task_check_mode):
                context = SimpleNamespace(task=SimpleNamespace(check_mode=task_check_mode))
                with patch.object(_task.TaskContext, "current", return_value=context):
                    self.assertIs(LookupModule._check_mode({"ansible_check_mode": option}), task_check_mode)

    def test_lookup_check_mode_rejects_an_unbound_token(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop("KSM_TOKEN", None)
            path = Path(directory) / "keeper.json"
            with patch.object(KeeperAnsible, "get_client") as get_client:
                with self.assertRaisesRegex(Exception, "check mode cannot redeem it"):
                    KeeperAnsible(task_vars={"keeper_config_file": str(path), "keeper_token": _token()},
                                  task_attributes={}, action_module=SimpleNamespace(), check_mode=True)
                get_client.assert_not_called()
            self.assertFalse(path.exists())

    def test_dr_cache_writes_are_disabled_only_in_check_mode(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"KSM_CACHE_DIR": directory}):
            path = Path(directory) / "ksm_cache.bin"
            path.write_bytes(b"existing cache")
            for check_mode in (True, False):
                with self.subTest(check_mode=check_mode):
                    self.action._task.check_mode = check_mode
                    keeper = KeeperAnsible(
                        task_vars={
                            "keeper_config_file": str(Path(directory) / "absent.json"),
                            "keeper_config": mock.MockConfig.make_base64(),
                            "keeper_use_cache": True,
                        },
                        action_module=self.action,
                    )
                    expected = (KeeperAnsible._check_mode_caching_post_function if check_mode
                                else KeeperAnsible._caching_post_function)
                    self.assertEqual(keeper.client.custom_post_function, expected)
                    self.assertTrue(keeper.using_cache)
                    self.assertEqual(path.read_bytes(), b"existing cache")

    def test_check_mode_cache_returns_a_successful_read_without_saving(self):
        transmission_key = SimpleNamespace(key=b"new key")
        response = SimpleNamespace(status_code=200, data=b"server response")
        with patch.object(SecretsManager, "post_function", return_value=response) as post, \
                patch.object(KSMCache, "save_cache") as save, \
                patch.object(KSMCache, "get_cached_data") as read:
            result = KeeperAnsible._check_mode_caching_post_function(
                "https://unused.test", transmission_key, "payload", False, "http://proxy.test"
            )
            self.assertIs(result, response)
            post.assert_called_once_with(
                "https://unused.test", transmission_key, "payload", False, "http://proxy.test"
            )
            save.assert_not_called()
            read.assert_not_called()

    def test_check_mode_cache_retains_offline_fallback_without_changing_the_file(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"KSM_CACHE_DIR": directory}):
            path = Path(directory) / "ksm_cache.bin"
            cached_data = b"k" * 32 + b"cached encrypted response"
            path.write_bytes(cached_data)
            transmission_key = SimpleNamespace(key=b"new key")
            with patch.object(KSMCache, "kms_cache_file_name", str(path)), \
                    patch.object(SecretsManager, "post_function", side_effect=ConnectionError("offline")), \
                    patch.object(KSMCache, "save_cache") as save:
                result = KeeperAnsible._check_mode_caching_post_function(
                    "https://unused.test", transmission_key, "payload"
                )
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.data, b"cached encrypted response")
                self.assertEqual(transmission_key.key, b"k" * 32)
                self.assertEqual(path.read_bytes(), cached_data)
                save.assert_not_called()


class KeeperCheckModeHelperTest(unittest.TestCase):

    def setUp(self):
        # The playbook framework reloads Ansible between runs, so refresh the exception class as well.
        from ansible.errors import AnsibleError
        error_patch = patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError)
        error_patch.start()
        self.addCleanup(error_patch.stop)

    @staticmethod
    def _vault_keeper(*records):
        # A KeeperAnsible whose reads get the records from a mock response. Any other request fails.
        keeper = _keeper()
        queue = mock.ResponseQueue(client=keeper.client)
        for _ in range(5):
            response = mock.Response()
            for record in records:
                response.add_record(record=record)
            queue.add_response(response)
        keeper.client.custom_post_function = queue.post_method
        return keeper

    def test_create_record_validates_payload_without_creating_a_record(self):
        keeper = _keeper()
        record = Record(version="v3").create_from_field_list(
            record_type="login", title="Dry Run Record", fields=[]
        )[0].get_record_create_obj()
        with patch.object(keeper.client, "get_folders", return_value=_folders()), \
                patch.object(keeper.client, "create_secret_with_options") as create_record, \
                patch.object(keeper.client, "_post_query") as post:
            uid = keeper.create_record(
                record, SHARED_UID, subfolder_uid=SUBFOLDER_UID, check_mode=True
            )
            self.assertIsNone(uid)
            create_record.assert_not_called()
            post.assert_not_called()

    def test_create_record_reports_missing_folder_and_owner_key_in_check_mode(self):
        record = Record(version="v3").create_from_field_list(
            record_type="login", title="Dry Run Record", fields=[]
        )[0].get_record_create_obj()
        for missing, message in (("folder", "folder key for SHARED_FOLDER_UID not found"),
                                 ("owner_key", "owner key is missing")):
            with self.subTest(missing=missing):
                keeper = _keeper()
                if missing == "owner_key":
                    keeper.client.config.delete(ConfigKeys.KEY_OWNER_PUBLIC_KEY)
                folders = [] if missing == "folder" else _folders()
                with patch.object(keeper.client, "get_folders", return_value=folders), \
                        patch.object(keeper.client, "create_secret_with_options") as create_record:
                    with self.assertRaisesRegex(Exception, message):
                        keeper.create_record(record, SHARED_UID, check_mode=True)
                    create_record.assert_not_called()

    def test_create_folder_predicts_new_and_existing_folders_without_creating(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                keeper = _keeper()
                with patch.object(keeper.client, "get_folders", return_value=_folders(existing)), \
                        patch.object(keeper.client, "create_folder") as create_folder, \
                        patch.object(keeper.client, "_post_query") as post:
                    uid, changed = keeper.create_folder(
                        "New Folder", SHARED_UID, subfolder_uid=SUBFOLDER_UID, check_mode=True
                    )
                    self.assertEqual(changed, not existing)
                    self.assertEqual(uid, "EXISTING_FOLDER_UID" if existing else None)
                    create_folder.assert_not_called()
                    post.assert_not_called()

    def test_create_folder_rejects_a_missing_shared_folder_in_check_mode(self):
        keeper = _keeper()
        with patch.object(keeper.client, "get_folders", return_value=[]), \
                patch.object(keeper.client, "create_folder") as create_folder:
            with self.assertRaisesRegex(Exception, "folder key for SHARED_FOLDER_UID not found"):
                keeper.create_folder("New Folder", SHARED_UID, check_mode=True)
            create_folder.assert_not_called()

    def test_create_folder_check_mode_reports_the_sdk_payload_error(self):
        keeper = _keeper()
        with patch.object(keeper.client, "get_folders", return_value=_folders()), \
                patch.object(keeper.client, "prepare_create_folder_payload",
                             side_effect=ValueError("payload rejected")) as prepare, \
                patch.object(keeper.client, "create_folder") as create_folder:
            with self.assertRaisesRegex(Exception, "payload rejected"):
                keeper.create_folder("New Folder", SHARED_UID, subfolder_uid=SUBFOLDER_UID, check_mode=True)
            prepare.assert_called_once()
            create_folder.assert_not_called()

    def test_set_validates_each_writable_field_without_saving_in_check_mode(self):
        for field_type in (KeeperFieldType.FIELD, KeeperFieldType.CUSTOM_FIELD, KeeperFieldType.NOTES):
            with self.subTest(field_type=field_type):
                keeper = _keeper()
                record = MagicMock()
                record.dict = {"notes": "original notes"}
                with patch.object(keeper, "get_record", return_value=record), \
                        patch.object(keeper.client, "save") as save:
                    keeper.set_value(
                        field_type, "password", "new value", uid="RECORD_UID", check_mode=True
                    )
                    save.assert_not_called()
                    if field_type == KeeperFieldType.NOTES:
                        self.assertEqual(record.dict["notes"], "new value")
                        record._update.assert_called_once()
                    elif field_type == KeeperFieldType.FIELD:
                        record.field.assert_called_once_with("password", "new value")
                    else:
                        record.custom_field.assert_called_once_with("password", "new value")

    def test_set_saves_only_a_changed_value(self):
        record = mock.Record(title="Set Record", record_type="login")
        record.field("password", "SAME_PASSWORD")
        record.custom_field("Note", "SAME_NOTE", field_type="text")
        for field_type, key, value, check_mode, changed in (
            (KeeperFieldType.FIELD, "password", "SAME_PASSWORD", False, False),
            (KeeperFieldType.FIELD, "password", ["SAME_PASSWORD"], False, False),
            (KeeperFieldType.FIELD, "password", "NEW_PASSWORD", False, True),
            (KeeperFieldType.FIELD, "password", "NEW_PASSWORD", True, True),
            (KeeperFieldType.FIELD, "password", "SAME_PASSWORD", True, False),
            (KeeperFieldType.CUSTOM_FIELD, "Note", "SAME_NOTE", False, False),
            (KeeperFieldType.CUSTOM_FIELD, "Note", "NEW_NOTE", False, True),
            (KeeperFieldType.NOTES, None, "NEW NOTES", False, True),
        ):
            with self.subTest(field_type=field_type, value=value, check_mode=check_mode):
                keeper = self._vault_keeper(record)
                with patch.object(keeper.client, "save") as save:
                    result = keeper.set_value(field_type, key, value, uid=record.uid, check_mode=check_mode)
                self.assertIs(result, changed)
                self.assertEqual(save.call_count, int(changed and not check_mode))

    def test_set_rejects_invalid_field_and_missing_record_without_saving(self):
        keeper = _keeper()
        with patch.object(keeper, "get_record", return_value=MagicMock()), \
                patch.object(keeper.client, "save") as save:
            with self.assertRaisesRegex(Exception, "Cannot save a file"):
                keeper.set_value(KeeperFieldType.FILE, "file.txt", "value", uid="RECORD_UID", check_mode=True)
            save.assert_not_called()
        with patch.object(keeper, "get_record", side_effect=ValueError("record not found")), \
                patch.object(keeper.client, "save") as save:
            with self.assertRaisesRegex(ValueError, "record not found"):
                keeper.set_value(KeeperFieldType.FIELD, "password", "value", uid="RECORD_UID", check_mode=True)
            save.assert_not_called()

    def test_remove_reads_record_but_does_not_delete_in_check_mode(self):
        keeper = _keeper()
        record = SimpleNamespace(uid="RECORD_UID", title="Record Title")
        with patch.object(keeper.client, "get_secrets", return_value=[record]) as get_secrets, \
                patch.object(keeper.client, "delete_secret") as delete:
            keeper.remove_record(uids="RECORD_UID", check_mode=True)
            get_secrets.assert_called_once()
            delete.assert_not_called()

    def test_remove_still_rejects_ambiguous_titles_in_check_mode(self):
        keeper = _keeper()
        records = [SimpleNamespace(uid="FIRST_UID", title="Duplicate Title"),
                   SimpleNamespace(uid="SECOND_UID", title="Duplicate Title")]
        with patch.object(keeper.client, "get_secrets", return_value=records), \
                patch.object(keeper.client, "delete_secret") as delete:
            with self.assertRaisesRegex(Exception, "Found multiple records"):
                keeper.remove_record(titles="Duplicate Title", check_mode=True)
            delete.assert_not_called()

    def test_remove_requires_the_server_to_confirm_the_delete(self):
        record = SimpleNamespace(uid="RECORD_UID", title="Record Title")
        for response, message in (
            ([{"recordUid": "RECORD_UID", "responseCode": "ok"}], None),
            ([{"recordUid": "RECORD_UID", "responseCode": "access_denied", "errorMessage": "Not allowed"}],
             r'did not delete record "Record Title" \(UID RECORD_UID\). It returned access_denied: Not allowed'),
            ([{"recordUid": "RECORD_UID", "responseCode": "not_found"}], "It returned not_found"),
            ([{"recordUid": "RECORD_UID"}], "It returned no response code"),
            (None, "did not confirm the delete"),
            ([], "did not confirm the delete"),
            ({"records": []}, "did not confirm the delete"),
            ([{"recordUid": "OTHER_UID", "responseCode": "ok"}], "did not confirm the delete"),
            ([{"recordUid": "RECORD_UID", "responseCode": "ok"}] * 2, "did not confirm the delete"),
        ):
            with self.subTest(response=response):
                keeper = _keeper()
                with patch.object(keeper.client, "get_secrets", return_value=[record]), \
                        patch.object(keeper.client, "delete_secret", return_value=response) as delete:
                    if message is None:
                        keeper.remove_record(uids="RECORD_UID")
                    else:
                        with self.assertRaisesRegex(RuntimeError, message):
                            keeper.remove_record(uids="RECORD_UID")
                    delete.assert_called_once_with(["RECORD_UID"])

    def test_helpers_use_the_task_check_mode_when_the_argument_is_missing(self):
        keeper = _keeper()
        keeper.check_mode = True
        keeper.using_cache = True
        record = SimpleNamespace(uid="RECORD_UID", title="Record Title", dict={"notes": "old"}, _update=MagicMock())
        create_object = Record(version="v3").create_from_field_list(
            record_type="login", title="Dry Run Record", fields=[]
        )[0].get_record_create_obj()
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(KeeperAnsible, "_cache_file_path", return_value=str(Path(directory) / "ksm_cache.bin")), \
                patch.object(keeper.client, "get_secrets", return_value=[record]), \
                patch.object(keeper.client, "get_folders", return_value=_folders()), \
                patch.object(keeper.client, "delete_secret") as delete, \
                patch.object(keeper.client, "save") as save, \
                patch.object(keeper.client, "create_secret_with_options") as create_record, \
                patch.object(keeper.client, "create_folder") as create_folder, \
                patch.object(KSMCache, "remove_cache_file") as remove_cache:
            (Path(directory) / "ksm_cache.bin").write_bytes(b"cache")
            keeper.remove_record(uids="RECORD_UID")
            self.assertTrue(keeper.set_value(KeeperFieldType.NOTES, None, "new", uid="RECORD_UID"))
            self.assertIsNone(keeper.create_record(create_object, SHARED_UID))
            self.assertEqual(keeper.create_folder("New Folder", SHARED_UID), (None, True))
            self.assertEqual(keeper.cleanup(), {"changed": True, "removed_ksm_cache": False})
            # A caller that asks for a real run still cannot change anything while the task is in check mode.
            keeper.remove_record(uids="RECORD_UID", check_mode=False)
            for mutation in (delete, save, create_record, create_folder, remove_cache):
                mutation.assert_not_called()

    def test_cleanup_predicts_a_removal_then_reports_a_real_removal_and_noop(self):
        keeper = object.__new__(KeeperAnsible)
        keeper.using_cache = True
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"KSM_CACHE_DIR": directory}):
            path = Path(directory) / "ksm_cache.bin"
            path.write_bytes(b"existing cache")
            with patch.object(KSMCache, "kms_cache_file_name", str(path)):
                self.assertEqual(
                    keeper.cleanup(check_mode=True), {"changed": True, "removed_ksm_cache": False}
                )
                self.assertEqual(path.read_bytes(), b"existing cache")
                self.assertEqual(
                    keeper.cleanup(), {"changed": True, "removed_ksm_cache": True}
                )
                self.assertFalse(path.exists())
                self.assertEqual(
                    keeper.cleanup(), {"changed": False, "removed_ksm_cache": False}
                )

    def test_cleanup_without_cache_does_not_remove_an_existing_file(self):
        keeper = object.__new__(KeeperAnsible)
        keeper.using_cache = False
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"KSM_CACHE_DIR": directory}):
            path = Path(directory) / "ksm_cache.bin"
            path.write_bytes(b"existing cache")
            self.assertEqual(keeper.cleanup(check_mode=True), {"changed": False})
            self.assertEqual(keeper.cleanup(), {"changed": False})
            self.assertEqual(path.read_bytes(), b"existing cache")

    def test_cleanup_checks_the_path_that_the_sdk_removes(self):
        keeper = object.__new__(KeeperAnsible)
        keeper.using_cache = True
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {"KSM_CACHE_DIR": str(Path(directory) / "env")}):
            (Path(directory) / "env").mkdir()
            sdk_path = Path(directory) / "sdk" / "ksm_cache.bin"
            sdk_path.parent.mkdir()
            env_path = Path(directory) / "env" / "ksm_cache.bin"
            with patch.object(KSMCache, "get_cache_file_path", return_value=str(sdk_path)):
                # SDK 17.4.0 and later prefer an assigned path to KSM_CACHE_DIR. cleanup must follow the SDK.
                sdk_path.write_bytes(b"cache")
                self.assertEqual(keeper.cleanup(), {"changed": True, "removed_ksm_cache": True})
                self.assertFalse(sdk_path.exists())
                env_path.write_bytes(b"other file")
                self.assertEqual(keeper.cleanup(), {"changed": False, "removed_ksm_cache": False})
                self.assertEqual(env_path.read_bytes(), b"other file")

    def test_cleanup_reports_no_change_when_another_host_removed_the_file_first(self):
        keeper = object.__new__(KeeperAnsible)
        keeper.using_cache = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ksm_cache.bin"
            path.write_bytes(b"cache")
            with patch.object(KeeperAnsible, "_cache_file_path", return_value=str(path)), \
                    patch.object(KSMCache, "remove_cache_file", side_effect=FileNotFoundError(str(path))):
                self.assertEqual(keeper.cleanup(), {"changed": False, "removed_ksm_cache": False})

    def test_cache_path_without_get_cache_file_path(self):
        # SDK versions before 17.3.0 have no get_cache_file_path(), and use kms_cache_file_name for every file.
        with patch.object(KSMCache, "get_cache_file_path", None), \
                patch.object(KSMCache, "kms_cache_file_name", "/assigned/ksm_cache.bin"):
            self.assertEqual(KeeperAnsible._cache_file_path(), "/assigned/ksm_cache.bin")


class _Task(object):
    def __init__(self, args, check_mode):
        self.args = args
        self.check_mode = check_mode
        self.async_val = 0
        self.action = "keeper_init"
        self.module_defaults = None


class KeeperInitCheckModeTest(unittest.TestCase):

    def test_keeper_init_skips_check_mode_when_actionbase_sets_the_instance_flag(self):
        self.addCleanup(_unload_ansible)
        plugin = importlib.import_module("keeper_secrets_manager_ansible.plugins.action.keeper_init")
        connection = types.SimpleNamespace(_shell=types.SimpleNamespace(tmpdir="/nonexistent"))
        # ActionBase.run of ansible-core 2.12 reads check_mode from the play context, later versions from the task.
        play_context = types.SimpleNamespace(check_mode=True)
        action = plugin.ActionModule(_Task({"token": "US:UNUSED_TOKEN"}, True), connection, play_context,
                                     None, None, None)
        # ansible-core 2.15 and earlier set this instance attribute to True in ActionBase.__init__.
        action._supports_check_mode = True
        with patch.object(KeeperAnsible, "__init__", side_effect=AssertionError("KeeperAnsible was created")) as init:
            with self.assertRaises(Exception) as context:
                action.run(task_vars={})
        # Compare by name: the test framework reloads the ansible modules, so the class object can differ.
        self.assertEqual(type(context.exception).__name__, "AnsibleActionSkip", repr(context.exception))
        init.assert_not_called()


class _UniqueKeyLoader(yaml.SafeLoader):
    # YAML keeps the last value of a duplicate key without an error. A merge can add a second key with no conflict.
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in keys:
                raise yaml.constructor.ConstructorError(None, None, "duplicate key {!r}".format(key),
                                                        key_node.start_mark)
            keys.add(key)
        return super(_UniqueKeyLoader, self).construct_mapping(node, deep=deep)


class KeeperDocumentationTest(unittest.TestCase):

    def test_documentation_has_no_duplicate_keys(self):
        paths = sorted(PLUGIN_DIR.glob("action/keeper_*.py")) + sorted(PLUGIN_DIR.glob("modules/keeper_*.py")) + \
            [PLUGIN_DIR / "lookup" / "keeper.py"]
        self.assertGreater(len(paths), 30)
        for path in paths:
            for node in ast.parse(path.read_text()).body:
                if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant):
                    continue
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ("DOCUMENTATION", "RETURN"):
                        with self.subTest(path=path.name, block=target.id):
                            yaml.load(node.value.value, Loader=_UniqueKeyLoader)


class KeeperCheckModePlaybookTest(unittest.TestCase):

    def _run(self, mode, existing_folder=False, cache_exists=True, cache_env_override=False):
        response = mock.Response()
        record = mock.Record(title="Check Mode Record", record_type="login")
        record.field("password", "ORIGINAL_PASSWORD")
        response.add_record(record=record)

        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ), ExitStack() as stack:
            os.environ.pop("KSM_CACHE_DIR", None)
            cache_directory = Path(directory) / "cache"
            cache_directory.mkdir()
            if cache_env_override:
                cache_directory = Path(directory) / "env-cache"
                cache_directory.mkdir()
                os.environ["KSM_CACHE_DIR"] = str(cache_directory)
            cache_path = cache_directory / "ksm_cache.bin"
            if cache_exists:
                cache_path.write_bytes(b"existing cache")
            config_path = Path(directory) / "initialized.yml"
            mutations = Path(directory) / "mutations.txt"
            endpoints = Path(directory) / "endpoints.txt"
            clients = Path(directory) / "clients.txt"

            # Ansible forks each task. A file captures calls that parent-side Mock counters cannot see.
            def mutation(name, result=None):
                def capture(*args, **kwargs):
                    with mutations.open("a") as fh:
                        fh.write(name + "\n")
                    return result
                return capture

            for method, result in (
                ("create_secret_with_options", "NEW_RECORD_UID"),
                ("save", None),
                ("create_folder", "NEW_FOLDER_UID"),
            ):
                stack.enter_context(patch.object(SecretsManager, method, side_effect=mutation(method, result)))

            def delete_secret(record_uids):
                mutation("delete_secret")()
                return _confirmed_delete(record_uids)

            stack.enter_context(patch.object(SecretsManager, "delete_secret", side_effect=delete_secret))
            stack.enter_context(patch.object(SecretsManager, "get_folders", return_value=_folders(existing_folder)))

            # Deny by default: every request that reaches the transport is recorded, whatever SDK method sent it.
            real_post_query = SecretsManager._post_query

            def post_query(client, path, payload):
                with endpoints.open("a") as fh:
                    fh.write(path + "\n")
                return real_post_query(client, path, payload)

            real_remove_cache = KSMCache.remove_cache_file
            real_cleanup = KeeperAnsible.cleanup

            def remove_cache():
                mutation("remove_cache_file")()
                real_remove_cache()

            def cleanup(keeper, *args, **kwargs):
                # Written by the mutation capture, so a capture that never fires fails the check-mode tests too.
                mutation("cleanup_called")()
                return real_cleanup(keeper, *args, **kwargs)

            stack.enter_context(patch.object(SecretsManager, "_post_query", autospec=True, side_effect=post_query))
            stack.enter_context(patch.object(KSMCache, "remove_cache_file", side_effect=remove_cache))
            stack.enter_context(patch.object(KSMCache, "save_cache", side_effect=mutation("save_cache")))
            stack.enter_context(patch.object(KeeperAnsible, "cleanup", autospec=True, side_effect=cleanup))

            playbook = "keeper_check_mode.yml"
            if mode in ("play", "task", "override"):
                plays = yaml.safe_load((PLAYBOOK_DIR / playbook).read_text())
                if mode == "play":
                    plays[0]["check_mode"] = True
                elif mode == "task":
                    for task in plays[0]["tasks"]:
                        if any(key.startswith("keeper_") for key in task):
                            task["check_mode"] = True
                else:
                    # A task can opt out of --check. keeper_set and keeper_remove then change the vault.
                    plays[0]["tasks"] = [task for task in plays[0]["tasks"] if "ansible.builtin.assert" not in task]
                    for task in plays[0]["tasks"]:
                        if "keeper_set" in task or "keeper_remove" in task:
                            task["check_mode"] = False
                destination = Path(directory) / "check-mode.yml"
                destination.write_text(yaml.safe_dump(plays))
                playbook = str(destination)

            framework = AnsibleTestFramework(
                playbook=playbook,
                check_mode=mode in ("cli", "override"),
                vars={
                    "keeper_config": mock.MockConfig.make_base64(),
                    "keeper_use_cache": True,
                    "keeper_cache_dir": str(Path(directory) / "cache"),
                    "record_uid": record.uid,
                    "config_filename": str(config_path),
                    "expect_check_mode": mode != "normal",
                    "expect_existing_folder": existing_folder,
                    "expect_cleanup_changed": cache_exists,
                },
                mock_responses=[response, response, response],
                client_log=str(clients),
            )
            recap, out, err = framework.run()
            return SimpleNamespace(
                recap=recap, output=out + err, mutations=_read_lines(mutations), endpoints=_read_lines(endpoints),
                clients=_read_clients(clients), config_written=config_path.exists(),
                cache=cache_path.read_bytes() if cache_path.exists() else None,
            )

    def _assert_check_mode(self, run, existing_folder=False, cache_exists=True):
        self.assertEqual(run.recap.get("failed"), 0, run.output)
        self.assertEqual(run.recap.get("ok"), 6, run.output)
        self.assertEqual(run.recap.get("changed"), 3 + int(not existing_folder) + int(cache_exists), run.output)
        self.assertEqual(run.recap.get("skipped"), 1, run.output)
        self.assertEqual(run.mutations, ["cleanup_called"])
        # keeper_set and keeper_remove read the record. Nothing else reaches the server.
        self.assertEqual(run.endpoints, ["get_secret", "get_secret"])
        # create, set, create_folder, remove, and cleanup each build a client. keeper_init is skipped.
        self.assertEqual(run.clients, [{"config": "InMemoryKeyValueStorage",
                                        "custom_post_function": CHECK_MODE_POST}] * 5)
        self.assertFalse(run.config_written)
        self.assertEqual(run.cache, b"existing cache" if cache_exists else None)

    def _assert_normal_mode(self, run, existing_folder=False, cache_exists=True):
        self.assertEqual(run.recap.get("failed"), 0, run.output)
        self.assertEqual(run.recap.get("ok"), 7, run.output)
        self.assertEqual(run.recap.get("changed"), 4 + int(not existing_folder) + int(cache_exists), run.output)
        self.assertEqual(run.recap.get("skipped"), 0, run.output)
        expected_calls = ["create_secret_with_options", "save"]
        if not existing_folder:
            expected_calls.append("create_folder")
        expected_calls += ["delete_secret", "cleanup_called"]
        if cache_exists:
            expected_calls.append("remove_cache_file")
        self.assertEqual(run.mutations, expected_calls)
        self.assertEqual(run.endpoints, ["get_secret"] * 3)
        # keeper_init removes the keeper_* variables, so its client has no DR cache.
        normal = {"config": "InMemoryKeyValueStorage", "custom_post_function": NORMAL_POST}
        self.assertEqual(run.clients, [normal] * 4 + [dict(normal, custom_post_function=None), normal])
        self.assertTrue(run.config_written)
        self.assertIsNone(run.cache)

    def test_cli_check_mode_never_mutates_vault_or_files(self):
        self._assert_check_mode(self._run("cli"))

    def test_play_check_mode_never_mutates_vault_or_files(self):
        self._assert_check_mode(self._run("play"))

    def test_task_check_mode_never_mutates_vault_or_files(self):
        self._assert_check_mode(self._run("task"))

    def test_check_mode_reports_existing_folder_and_missing_cache_as_unchanged(self):
        self._assert_check_mode(self._run("cli", existing_folder=True, cache_exists=False),
                                existing_folder=True, cache_exists=False)

    def test_check_mode_preserves_cache_in_environment_override_directory(self):
        self._assert_check_mode(self._run("cli", cache_env_override=True))

    def test_normal_mode_reports_and_performs_all_six_mutations(self):
        self._assert_normal_mode(self._run("normal"))

    def test_normal_mode_reports_existing_folder_and_missing_cache_as_unchanged(self):
        self._assert_normal_mode(self._run("normal", existing_folder=True, cache_exists=False),
                                 existing_folder=True, cache_exists=False)

    def test_task_that_opts_out_of_check_mode_changes_the_vault(self):
        run = self._run("override")
        self.assertEqual(run.recap.get("failed"), 0, run.output)
        self.assertEqual(run.recap.get("ok"), 5, run.output)
        self.assertEqual(run.recap.get("changed"), 5, run.output)
        self.assertEqual(run.recap.get("skipped"), 1, run.output)
        self.assertEqual(run.mutations, ["save", "delete_secret", "cleanup_called"])
        self.assertEqual(run.endpoints, ["get_secret", "get_secret"])
        check = {"config": "InMemoryKeyValueStorage", "custom_post_function": CHECK_MODE_POST}
        normal = dict(check, custom_post_function=NORMAL_POST)
        self.assertEqual(run.clients, [check, normal, check, normal, check])
        self.assertFalse(run.config_written)
        self.assertEqual(run.cache, b"existing cache")


class KeeperLookupCheckModePlaybookTest(unittest.TestCase):

    def _run(self, playbook, check_mode, config, play_check_mode=None, task_check_mode=None, cache=True):
        response = mock.Response()
        record = mock.Record(title="Lookup Record", record_type="login")
        record.field("password", "LOOKUP_PASSWORD")
        response.add_record(record=record)

        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop("KSM_CACHE_DIR", None)
            os.environ.pop("KSM_TOKEN", None)
            cache_path = Path(directory) / "ksm_cache.bin"
            cache_path.write_bytes(b"existing cache")
            config_path = Path(directory) / "keeper.json"
            clients = Path(directory) / "clients.txt"

            if play_check_mode is not None or task_check_mode is not None:
                plays = yaml.safe_load((PLAYBOOK_DIR / playbook).read_text())
                if play_check_mode is not None:
                    plays[0]["check_mode"] = play_check_mode
                if task_check_mode is not None:
                    for task in plays[0]["tasks"]:
                        task["check_mode"] = task_check_mode
                destination = Path(directory) / "playbook.yml"
                destination.write_text(yaml.safe_dump(plays))
                playbook = str(destination)

            variables = {"record_uid": record.uid, "keeper_config_file": str(config_path)}
            if config == "bound":
                variables["keeper_config"] = mock.MockConfig.make_base64()
            else:
                # The test inventory sets bound keys for my_systems. Empty values leave only the token.
                variables.update({"keeper_token": _token(), "keeper_client_id": "", "keeper_private_key": "",
                                  "keeper_app_key": ""})
            if cache:
                variables.update({"keeper_use_cache": True, "keeper_cache_dir": directory})

            # AnsibleTestFramework reloads Ansible after each run, but not this package. An AnsibleError that
            # KeeperAnsible raises must be the class of the run, or the worker dies instead of failing the task.
            from ansible.errors import AnsibleError
            with patch("keeper_secrets_manager_ansible.AnsibleError", AnsibleError):
                recap, out, err = AnsibleTestFramework(
                    playbook=playbook, check_mode=check_mode, vars=variables, mock_responses=[response],
                    client_log=str(clients),
                ).run()
            return SimpleNamespace(recap=recap, output=out + err, clients=_read_clients(clients),
                                   config_written=config_path.exists(), cache=cache_path.read_bytes())

    def test_lookup_in_check_mode_reads_without_refreshing_the_cache(self):
        run = self._run("keeper_check_mode_lookup.yml", check_mode=True, config="bound")
        self.assertEqual(run.recap.get("ok"), 1, run.output)
        self.assertEqual(run.recap.get("ignored"), 0, run.output)
        self.assertEqual(run.clients, [{"config": "InMemoryKeyValueStorage",
                                        "custom_post_function": CHECK_MODE_POST}])
        self.assertEqual(run.cache, b"existing cache")
        self.assertFalse(run.config_written)

    def test_lookup_in_check_mode_rejects_an_unbound_token(self):
        run = self._run("keeper_check_mode_lookup.yml", check_mode=True, config="token")
        self.assertEqual(run.recap.get("ignored"), 1, run.output)
        self.assertIn("It has a one-time token, and check mode cannot redeem it", run.output)
        self.assertEqual(run.clients, [])
        self.assertFalse(run.config_written)

    def test_lookup_in_a_normal_run_uses_the_dr_cache(self):
        run = self._run("keeper_check_mode_lookup.yml", check_mode=False, config="bound")
        self.assertEqual(run.recap.get("ok"), 1, run.output)
        self.assertEqual(run.clients, [{"config": "InMemoryKeyValueStorage", "custom_post_function": NORMAL_POST}])

    def test_lookup_sees_a_play_check_mode_only_with_the_task_context(self):
        # Before ansible-core 2.19, a lookup sees only the --check option.
        expected = CHECK_MODE_POST if _task_context_available() else NORMAL_POST
        run = self._run("keeper_check_mode_lookup.yml", check_mode=False, config="bound", play_check_mode=True)
        self.assertEqual(run.recap.get("ok"), 1, run.output)
        self.assertEqual(run.clients, [{"config": "InMemoryKeyValueStorage", "custom_post_function": expected}])

    def test_lookup_follows_a_task_that_opts_out_of_check_mode_with_the_task_context(self):
        # Without the task context, the lookup follows --check: the safe direction.
        expected = NORMAL_POST if _task_context_available() else CHECK_MODE_POST
        run = self._run("keeper_check_mode_lookup.yml", check_mode=True, config="bound", task_check_mode=False)
        self.assertEqual(run.recap.get("ok"), 1, run.output)
        self.assertEqual(run.clients, [{"config": "InMemoryKeyValueStorage", "custom_post_function": expected}])

    def test_modules_that_never_contact_the_vault_run_in_check_mode_with_a_token(self):
        run = self._run("keeper_check_mode_local.yml", check_mode=True, config="token")
        self.assertEqual(run.recap.get("ok"), 3, run.output)
        self.assertEqual(run.recap.get("failed"), 0, run.output)
        self.assertEqual([client["config"] for client in run.clients], ["InMemoryKeyValueStorage"] * 3)
        self.assertFalse(run.config_written)
        self.assertEqual(run.cache, b"existing cache")
