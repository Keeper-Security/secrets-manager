import ast
import importlib
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

import yaml

from keeper_secrets_manager_ansible import KeeperAnsible


UID = "RECORD_UID"
TITLE = "Record 1"


def _record(uid=UID, title=TITLE):
    return types.SimpleNamespace(uid=uid, title=title)


def _ok(uid=UID):
    return {"recordUid": uid, "responseCode": "ok"}


def tearDownModule():
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)


class KeeperRemoveRecordTest(unittest.TestCase):

    def setUp(self):
        self.keeper = object.__new__(KeeperAnsible)
        self.keeper.client = MagicMock()
        self.keeper.client.get_secrets.return_value = [_record()]
        self.keeper.client.delete_secret.return_value = [_ok()]

    def test_delete_by_uid_returns_changed_and_record_identity(self):
        result = self.keeper.remove_record(uids=UID)
        self.assertEqual(result, {"changed": True, "record_uid": UID, "record_title": TITLE})
        self.keeper.client.get_secrets.assert_called_once_with([UID])
        self.keeper.client.delete_secret.assert_called_once_with([UID])

    def test_delete_by_title_reads_all_records_and_deletes_only_the_match(self):
        self.keeper.client.get_secrets.return_value.append(_record("OTHER_UID", "Keep Me"))
        result = self.keeper.remove_record(titles=TITLE)
        self.assertEqual(result, {"changed": True, "record_uid": UID, "record_title": TITLE})
        self.keeper.client.get_secrets.assert_called_once_with()
        self.keeper.client.delete_secret.assert_called_once_with([UID])

    def test_missing_uid_or_title_is_a_no_op(self):
        for selector in ({"uids": "MISSING_UID"}, {"titles": "Missing Title"}):
            for records in ([], [_record()]):
                with self.subTest(selector=selector, records=records):
                    self.keeper.client.get_secrets.return_value = records
                    result = self.keeper.remove_record(**selector)
                    self.assertIs(result["changed"], False)
                    self.assertNotIn("failed", result)
                    self.assertIn("Nothing was deleted", result["msg"])
        self.keeper.client.delete_secret.assert_not_called()

    def test_duplicate_title_fails_with_every_matching_uid(self):
        self.keeper.client.get_secrets.return_value.append(_record("TWIN_UID"))
        with self.assertRaises(Exception) as error:
            self.keeper.remove_record(titles=TITLE)
        self.assertIn(UID, str(error.exception))
        self.assertIn("TWIN_UID", str(error.exception))
        self.keeper.client.delete_secret.assert_not_called()

    def test_check_mode_predicts_a_change_without_deleting(self):
        for selector in ({"uids": UID}, {"titles": TITLE}):
            with self.subTest(selector=selector):
                self.assertEqual(
                    self.keeper.remove_record(check_mode=True, **selector),
                    {"changed": True, "record_uid": UID, "record_title": TITLE},
                )
        self.keeper.client.delete_secret.assert_not_called()

    def test_check_mode_missing_record_is_a_no_op(self):
        self.keeper.client.get_secrets.return_value = []
        for selector in ({"uids": UID}, {"titles": TITLE}):
            with self.subTest(selector=selector):
                result = self.keeper.remove_record(check_mode=True, **selector)
                self.assertIs(result["changed"], False)
        self.keeper.client.delete_secret.assert_not_called()

    def test_check_mode_still_rejects_duplicate_titles(self):
        self.keeper.client.get_secrets.return_value.append(_record("TWIN_UID"))
        with self.assertRaises(Exception) as error:
            self.keeper.remove_record(titles=TITLE, check_mode=True)
        self.assertIn("TWIN_UID", str(error.exception))
        self.keeper.client.delete_secret.assert_not_called()

    def test_non_ok_status_fails_with_the_code_and_server_message(self):
        for code in ("access_denied", "not_found", "error", "OK"):
            with self.subTest(code=code):
                self.keeper.client.delete_secret.return_value = [{
                    "recordUid": UID,
                    "responseCode": code,
                    "errorMessage": "User does not have permission to delete this record",
                }]
                with self.assertRaises(Exception) as error:
                    self.keeper.remove_record(uids=UID)
                self.assertIn(code, str(error.exception))
                self.assertIn("User does not have permission", str(error.exception))
                self.assertIn(UID, str(error.exception))

    def test_status_without_a_code_keeps_the_server_message(self):
        self.keeper.client.delete_secret.return_value = [{
            "recordUid": UID, "errorMessage": "The delete was refused",
        }]
        with self.assertRaises(Exception) as error:
            self.keeper.remove_record(uids=UID)
        self.assertIn("no response code", str(error.exception))
        self.assertIn("The delete was refused", str(error.exception))

    def test_unconfirmed_or_malformed_delete_response_is_not_a_success(self):
        for response in (
            None, [], {}, "ok", [None, "ok"],
            [{"responseCode": "ok"}], [_ok("OTHER_UID")],
            [_ok(), {"recordUid": UID, "responseCode": "access_denied"}],
        ):
            with self.subTest(response=response):
                self.keeper.client.delete_secret.return_value = response
                with self.assertRaises(Exception) as error:
                    self.keeper.remove_record(uids=UID)
                self.assertIn("did not confirm", str(error.exception))

    def test_status_is_matched_by_uid_not_position(self):
        self.keeper.client.delete_secret.return_value = [
            None, {"recordUid": "OTHER_UID", "responseCode": "access_denied"}, _ok(),
        ]
        self.assertIs(self.keeper.remove_record(uids=UID)["changed"], True)

    def test_lookup_failure_does_not_become_a_missing_record(self):
        self.keeper.client.get_secrets.side_effect = RuntimeError("Cannot reach Keeper")
        with self.assertRaises(Exception) as error:
            self.keeper.remove_record(uids=UID)
        self.assertIn("Cannot reach Keeper", str(error.exception))
        self.keeper.client.delete_secret.assert_not_called()

    def test_delete_exception_does_not_report_success(self):
        self.keeper.client.delete_secret.side_effect = RuntimeError("Connection lost")
        with self.assertRaises(Exception) as error:
            self.keeper.remove_record(uids=UID)
        self.assertIn("Connection lost", str(error.exception))

    def test_registered_cache_is_not_authoritative_for_a_delete(self):
        with patch.object(self.keeper, "decrypt", return_value=[_record()]) as decrypt:
            self.keeper.client.get_secrets.return_value = []
            result = self.keeper.remove_record(uids=UID, cache="stale-cache")
        self.assertIs(result["changed"], False)
        decrypt.assert_not_called()
        self.keeper.client.get_secrets.assert_called_once_with([UID])
        self.keeper.client.delete_secret.assert_not_called()

    def test_cached_title_cannot_hide_duplicates_in_the_vault(self):
        self.keeper.client.get_secrets.return_value.append(_record("TWIN_UID"))
        with patch.object(self.keeper, "decrypt", return_value=[_record()]):
            with self.assertRaises(Exception) as error:
                self.keeper.remove_record(titles=TITLE, cache="partial-cache")
        self.assertIn("TWIN_UID", str(error.exception))
        self.keeper.client.delete_secret.assert_not_called()

    def test_other_record_lookups_still_fail_when_a_record_is_missing(self):
        self.keeper.client.get_secrets.return_value = []
        for selector in ({"uids": UID}, {"titles": TITLE}):
            with self.subTest(selector=selector):
                with self.assertRaises(Exception):
                    self.keeper.get_records(**selector)


class KeeperRemoveActionTest(unittest.TestCase):

    def _run(self, args, check_mode=False, result=None, error=None, module_defaults=None):
        plugin = importlib.import_module("keeper_secrets_manager_ansible.plugins.action.keeper_remove")
        task = types.SimpleNamespace(
            args=dict(args), check_mode=check_mode, async_val=0, action="keeper_remove",
            module_defaults=module_defaults,
        )
        connection = types.SimpleNamespace(_shell=types.SimpleNamespace(tmpdir="/nonexistent"))
        context = types.SimpleNamespace(check_mode=check_mode)
        action = plugin.ActionModule(task, connection, context, None, None, None)
        with patch.object(KeeperAnsible, "__init__", return_value=None) as init, \
                patch.object(KeeperAnsible, "remove_record", return_value=result, side_effect=error) as remove:
            output = action.run(task_vars={})
        return output, init, remove, task

    def test_helper_result_is_returned_and_task_args_are_not_modified(self):
        expected = {"changed": True, "record_uid": UID, "record_title": TITLE}
        output, _, remove, task = self._run({"title": TITLE, "cache": "cache"}, result=expected)
        self.assertEqual(output, expected)
        self.assertEqual(task.args, {"title": TITLE, "cache": "cache"})
        remove.assert_called_once_with(uids=None, titles=TITLE, cache="cache", check_mode=False)

    def test_check_mode_is_passed_to_the_helper(self):
        output, _, remove, _ = self._run({"uid": UID}, check_mode=True, result={"changed": True})
        self.assertIs(output["changed"], True)
        remove.assert_called_once_with(uids=UID, titles=None, cache=None, check_mode=True)

    def test_registered_cache_bytes_are_accepted_without_coercion(self):
        cache = b"encrypted-cache"
        output, _, remove, _ = self._run({"uid": UID, "cache": cache}, result={"changed": False})
        self.assertIs(output["changed"], False)
        remove.assert_called_once_with(uids=UID, titles=None, cache=cache, check_mode=False)

    def test_lookup_and_delete_errors_are_normal_task_failures(self):
        output, _, _, _ = self._run({"uid": UID}, error=RuntimeError("access_denied: Cannot delete"))
        self.assertEqual(output, {
            "failed": True, "changed": False,
            "msg": "Could not remove record: access_denied: Cannot delete",
        })

    def test_invalid_options_fail_before_initializing_the_client(self):
        for args in (
            {}, {"uid": UID, "title": TITLE}, {"uid": None}, {"title": None},
            {"uid": ""}, {"uid": " "}, {"uid": " RECORD_UID "}, {"title": ""},
            {"uid": [UID]}, {"uid": 123}, {"title": True}, {"uid": UID, "cache": {}},
            {"uid": UID, "titel": TITLE},
        ):
            with self.subTest(args=args):
                output, init, remove, _ = self._run(args)
                self.assertIs(output["failed"], True)
                self.assertIs(output["changed"], False)
                self.assertIn("msg", output)
                init.assert_not_called()
                remove.assert_not_called()

    def test_group_defaults_for_other_modules_are_ignored(self):
        output, _, remove, _ = self._run(
            {"uid": UID, "force": True}, result={"changed": False},
            module_defaults=[{"group/keepersecurity.keeper_secrets_manager.keeper": {"force": True}}],
        )
        self.assertIs(output["changed"], False)
        remove.assert_called_once()


class KeeperRemoveDocumentationTest(unittest.TestCase):

    def _docs(self, kind):
        import keeper_secrets_manager_ansible.plugins
        path = os.path.join(os.path.dirname(keeper_secrets_manager_ansible.plugins.__file__),
                            kind, "keeper_remove.py")
        with open(path) as handle:
            tree = ast.parse(handle.read())
        return {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in ("DOCUMENTATION", "EXAMPLES", "RETURN")
        }

    def test_action_and_module_documentation_match(self):
        self.assertEqual(self._docs("action"), self._docs("modules"))

    def test_return_documents_actual_results_not_existed(self):
        result = yaml.safe_load(self._docs("action")["RETURN"])
        self.assertEqual(set(result), {"changed", "record_uid", "record_title", "msg"})
        self.assertEqual(result["changed"]["type"], "bool")

    def test_documentation_explains_idempotency_check_mode_and_cache_freshness(self):
        documentation = self._docs("action")["DOCUMENTATION"]
        self.assertIn("check_mode", yaml.safe_load(documentation)["attributes"])
        self.assertIn("does not exist", documentation)
        self.assertIn("current vault", documentation)
