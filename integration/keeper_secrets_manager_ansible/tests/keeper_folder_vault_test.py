import os
import tempfile

from . import keeper_update_folder_playbook_test as playbook_tests
from .folder_fake_server import FakeKeeperServer


# A password for these tests only. The inline !vault values in keeper_folder_vault.yml are encrypted with it.
VAULT_PASSWORD = "keeper-folder-vault-test-only"

SHARED_FOLDER_UID = "SHARED_FOLDER_UID"
FOLDER_UID = "FOLDER_UID"
SIBLING_UID = "SIBLING_UID"


class KeeperFolderVaultTest(playbook_tests._PlaybookTestCase):
    """
    Inline !vault values in the task args of keeper_get_folder, keeper_update_folder, and keeper_delete_folder.

    Before ansible-core 2.19, such a value reaches the action plugin as an AnsibleVaultEncryptedUnicode, which is not
    a str. The option check must accept it as a string, and the value must be used decrypted: the right folder must
    be found, renamed, and deleted.
    """

    def test_inline_vault_values_find_rename_and_delete_the_right_folder(self):
        server = FakeKeeperServer(folders=[
            {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
            {"uid": FOLDER_UID, "name": "Staging", "parent": SHARED_FOLDER_UID},
            {"uid": SIBLING_UID, "name": "Databases", "parent": SHARED_FOLDER_UID},
        ])
        # mkstemp makes the file with mode 0600. It must not be executable: Ansible runs an executable password file.
        fd, password_file = tempfile.mkstemp(prefix="ksm_vault_password_", suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write(VAULT_PASSWORD + "\n")
        saved = os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE")
        # The framework imports ansible again for each run, so the password file takes effect.
        os.environ["ANSIBLE_VAULT_PASSWORD_FILE"] = password_file
        try:
            result, out, err = self.run_playbook(server, "keeper_folder_vault.yml", {
                "shared_folder_uid": SHARED_FOLDER_UID,
                "folder_uid": FOLDER_UID,
            })

            # 2 lookups, a rename, a delete, and the assert.
            self.assert_recap(result, out, err, ok=5, changed=2)
            self.assertEqual(server.calls("update_folder"),
                             [{"path": "update_folder", "folder_uid": FOLDER_UID, "folder_name": "Production"}],
                             "the rename must use the decrypted UID and the decrypted new name")
            self.assertEqual(server.calls("delete_folder"),
                             [{"path": "delete_folder", "folder_uids": [FOLDER_UID], "force": False}],
                             "the delete must use the decrypted UID")
            self.assertEqual(server.folders(), [
                {"uid": SHARED_FOLDER_UID, "name": "Infrastructure", "parent": None},
                {"uid": SIBLING_UID, "name": "Databases", "parent": SHARED_FOLDER_UID},
            ], "only the vaulted folder may be renamed and deleted")
        finally:
            if saved is None:
                os.environ.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
            else:
                os.environ["ANSIBLE_VAULT_PASSWORD_FILE"] = saved
            os.remove(password_file)
            server.cleanup()
