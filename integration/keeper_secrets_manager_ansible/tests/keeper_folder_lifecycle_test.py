import inspect
import sys
import unittest
from keeper_secrets_manager_core.dto.dtos import KeeperFolder
from .ansible_test_framework import AnsibleTestFramework
from .folder_fake_server import FakeKeeperServer

# SDK 18.0.0 added AES-GCM subfolders, and KeeperFolder.use_gcm with them. Older SDKs cannot read one.
SDK_READS_GCM_FOLDERS = "use_gcm" in inspect.signature(KeeperFolder.__init__).parameters


class KeeperFolderLifecycleTest(unittest.TestCase):
    """
    Runs keeper_create_folder, keeper_get_folder, keeper_update_folder, and keeper_delete_folder together in one
    playbook, against FakeKeeperServer. Only the network is fake: the real SDK encrypts and decrypts every folder
    key, name, and payload, and each task sees the changes that the tasks before it made.
    """

    @classmethod
    def setUpClass(cls):
        # A test module that imports a plugin when it loads (keeper_redact_test.py, for example) starts ansible's
        # plugin loader with the default paths, before AnsibleTestFramework sets the plugin paths. Unload the ansible
        # modules, so the first playbook run in this class loads them again with the right paths, in any test order.
        for module in list(sys.modules):
            if module.startswith("ansible"):
                sys.modules.pop(module, None)

    def test_folder_lifecycle(self):
        server = FakeKeeperServer(
            folders=[
                {"uid": "SHARED_FOLDER_UID", "name": "Infrastructure", "parent": None},
                {"uid": "SUBFOLDER_UID", "name": "Databases", "parent": "SHARED_FOLDER_UID"},
            ],
            records=[
                {"uid": "RECORD_UID", "title": "Database Login", "folder": "SHARED_FOLDER_UID",
                 "inner": "SUBFOLDER_UID"},
            ],
        )
        try:
            with server.patch():
                a = AnsibleTestFramework(
                    playbook="keeper_folder_lifecycle.yml",
                    vars={
                        "shared_folder_uid": "SHARED_FOLDER_UID",
                        "subfolder_uid": "SUBFOLDER_UID",
                    },
                )
                result, out, err = a.run()

            # 13 tasks. The 2 that fail on purpose are counted as ok, and as ignored.
            self.assertEqual(result.get("failed"), 0, "a task failed: " + out + err)
            self.assertEqual(result.get("ignored"), 2, "the 2 expected failures did not happen")
            self.assertEqual(result.get("ok"), 13, "not every task ran")
            # keeper_create_folder, the first rename, and the first delete.
            self.assertEqual(result.get("changed"), 3, "3 tasks should change the vault")

            self.assertEqual(
                [c["folder_name"] for c in server.calls("update_folder")], ["Production"],
                "the second rename must not send an update")
            self.assertEqual(len(server.calls("create_folder")), 1)
            deletes = server.calls("delete_folder")
            self.assertEqual(len(deletes), 1, "only the first delete of the empty folder may reach the server")
            self.assertFalse(deletes[0]["force"])

            self.assertEqual(
                sorted(f["uid"] for f in server.folders()), ["SHARED_FOLDER_UID", "SUBFOLDER_UID"],
                "the non-empty folder must still exist, and the new folder must be gone")
            self.assertEqual([r["uid"] for r in server.records()], ["RECORD_UID"])
        finally:
            server.cleanup()

    @unittest.skipUnless(SDK_READS_GCM_FOLDERS, "this SDK version cannot read AES-GCM subfolders")
    def test_rename_gcm_subfolder(self):
        """
        A subfolder that a newer client created uses AES-GCM, not AES-CBC. The rename must send the new name in
        the folder's own format, or the vault cannot decrypt the name. keeper_update_folder passes the folder
        list from get_folders to the SDK, so the SDK can see the format of the folder.
        """
        server = FakeKeeperServer(
            folders=[
                {"uid": "SHARED_FOLDER_UID", "name": "Infrastructure", "parent": None},
                {"uid": "GCM_FOLDER_UID", "name": "Old Name", "parent": "SHARED_FOLDER_UID", "gcm": True},
            ],
        )
        try:
            with server.patch():
                a = AnsibleTestFramework(
                    playbook="keeper_folder_gcm_rename.yml",
                    vars={"shared_folder_uid": "SHARED_FOLDER_UID"},
                )
                result, out, err = a.run()

            self.assertEqual(result.get("failed"), 0, "a task failed: " + out + err)
            self.assertEqual(result.get("ok"), 4, "not every task ran")
            self.assertEqual(server.folder("GCM_FOLDER_UID")["name"], "New Name")
        finally:
            server.cleanup()
