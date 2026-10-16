import os
import shutil
import tempfile

import keeper_secrets_manager_ansible.plugins
from . import keeper_update_folder_playbook_test as playbook_tests
from .folder_fake_server import FakeKeeperServer


COMPONENT_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
RUNTIME_YML = os.path.join(COMPONENT_DIR, "ansible_galaxy", "keepersecurity", "keeper_secrets_manager", "meta",
                           "runtime.yml")
PLUGINS_DIR = os.path.dirname(os.path.realpath(keeper_secrets_manager_ansible.plugins.__file__))
COLLECTION = ("keepersecurity", "keeper_secrets_manager")

SHARED_FOLDER_UID = "SHARED_FOLDER_UID"
DATABASES_UID = "DATABASES_UID"


class KeeperUpdateFolderGroupDefaultsTest(playbook_tests._PlaybookTestCase):
    """
    group module_defaults for the keepersecurity.keeper_secrets_manager action group, end to end. The test builds a
    collection layout in a temp dir, with the real meta/runtime.yml (which defines the action group) and the package's
    plugins as symlinks, so that Ansible runs the modules by their full collection names and applies the group
    defaults, as it does for the installed collection.
    """

    def _make_collection_path(self):
        root = tempfile.mkdtemp(prefix="ksm_collections_")
        collection = os.path.join(root, "ansible_collections", *COLLECTION)
        os.makedirs(os.path.join(collection, "meta"))
        os.makedirs(os.path.join(collection, "plugins"))
        shutil.copyfile(RUNTIME_YML, os.path.join(collection, "meta", "runtime.yml"))
        for name in ("action", "modules"):
            os.symlink(os.path.join(PLUGINS_DIR, name), os.path.join(collection, "plugins", name))
        return root

    @staticmethod
    def _remove_collection_path(root):
        # Remove the symlinks first, so that nothing can ever delete the package's real plugin files.
        plugins = os.path.join(root, "ansible_collections", *COLLECTION, "plugins")
        for name in ("action", "modules"):
            link = os.path.join(plugins, name)
            if os.path.islink(link):
                os.unlink(link)
        shutil.rmtree(root)

    def test_group_defaults_are_used_or_ignored_by_each_folder_module(self):
        """
        keeper_create_folder and keeper_get_folder use the default shared_folder_uid. keeper_update_folder and
        keeper_delete_folder do not have shared_folder_uid or cache, and ignore them. A misspelled option in a task
        still fails, and the error lists only the misspelled option, not the group defaults. The second play gives the
        same defaults as one template string.
        """
        server = FakeKeeperServer(folders=[
            {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
            {"uid": DATABASES_UID, "name": "Databases", "parent": SHARED_FOLDER_UID},
        ])
        root = self._make_collection_path()
        saved = os.environ.get("ANSIBLE_COLLECTIONS_PATH")
        # The framework imports ansible again for each run, so the new collection path takes effect.
        os.environ["ANSIBLE_COLLECTIONS_PATH"] = root
        try:
            result, out, err = self.run_playbook(server, "keeper_update_folder_group_defaults.yml", {
                "shared_folder_uid": SHARED_FOLDER_UID,
                "databases_folder_uid": DATABASES_UID,
            })

            # Play 1: 8 tasks, 2 of them fail on purpose. Play 2: 3 tasks.
            self.assert_recap(result, out, err, ok=11, changed=4, ignored=2)

            creates = server.calls("create_folder")
            self.assertEqual(len(creates), 1, creates)
            self.assertEqual((creates[0]["shared_folder_uid"], creates[0]["parent_uid"], creates[0]["folder_name"]),
                             (SHARED_FOLDER_UID, None, "Group Defaults"),
                             "keeper_create_folder must create the folder in the default shared folder")
            created_uid = creates[0]["folder_uid"]

            self.assertEqual([(c["folder_uid"], c["folder_name"]) for c in server.calls("update_folder")],
                             [(created_uid, "Group Defaults Renamed"), (DATABASES_UID, "Data Stores")],
                             "only the 2 valid renames may reach the server")
            self.assertEqual(server.calls("delete_folder"),
                             [{"path": "delete_folder", "folder_uids": [created_uid], "force": False}],
                             "only the valid delete may reach the server, without force")
            self.assertEqual(server.folders(), [
                {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
                {"uid": DATABASES_UID, "name": "Data Stores", "parent": SHARED_FOLDER_UID},
            ])
        finally:
            if saved is None:
                os.environ.pop("ANSIBLE_COLLECTIONS_PATH", None)
            else:
                os.environ["ANSIBLE_COLLECTIONS_PATH"] = saved
            self._remove_collection_path(root)
            server.cleanup()
        self.assertTrue(os.path.isdir(os.path.join(PLUGINS_DIR, "action")), "the real plugin dir must be untouched")
