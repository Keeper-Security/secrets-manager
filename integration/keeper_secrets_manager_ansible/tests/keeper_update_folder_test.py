import contextlib
import datetime
import inspect
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import call, create_autospec, patch

import yaml
from ansible.errors import AnsibleError
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.dto.dtos import KeeperFolder
from keeper_secrets_manager_core.exceptions import KeeperError

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperArgumentError, KeeperFolderError
from keeper_secrets_manager_ansible.plugins.action import keeper_update_folder as action_plugin
from keeper_secrets_manager_ansible.plugins.action.keeper_update_folder import ActionModule
from keeper_secrets_manager_ansible.plugins.modules import keeper_update_folder as docs_stub



def tearDownModule():
    """
    Unload the ansible modules, as AnsibleTestFramework does after each playbook run. This file imports the action
    plugin when it loads, which starts ansible's plugin loader with the default paths. So a playbook test that runs
    after this file must load a new plugin loader, with the Keeper plugin paths.
    """
    for name in list(sys.modules):
        if name.startswith("ansible") or name.startswith("keeper_secrets_manager_ansible.plugins.action."):
            sys.modules.pop(name, None)

SHARED_INFRA = "SHARED_INFRA_UID"
SHARED_APPS = "SHARED_APPS_UID"
DATABASES = "DATABASES_UID"
STAGING = "STAGING_UID"
PRODUCTION = "PRODUCTION_UID"
EU = "EU_UID"
FRANKFURT = "FRANKFURT_UID"
APPS_STAGING = "APPS_STAGING_UID"
ARCHIVE = "ARCHIVE_UID"
MISSING = "MISSING_FOLDER_UID"

NOT_FOUND = "The folder {} was not found, or it is not shared to this KSM application."
BLANK_NAME = "The new_folder_name is blank."
BLANK_UID = "The folder_uid is blank."
STAGING_LABEL = '"Infrastructure/Databases/Staging" (UID STAGING_UID)'

NULL_OPTION = "The {} option is null. Give it a value, or leave the option out of the task."
WRONG_TYPE = ("The {} option must be a string, but it is {}. Put quotes around the value, or use the string "
              "filter.")
SUPPORTED = "Supported parameters include: "
OPTIONS = {"folder_uid", "new_folder_name"}
GROUP = "group/keepersecurity.keeper_secrets_manager.keeper_secrets_manager"

# Values that a str option must reject, and how the message names each kind. An int is rejected too: YAML changes the
# text of some numbers that have no quotes (007 becomes 7), so the text that the author wrote cannot come back.
WRONG_TYPES = [
    (["Prod", "EU"], "a list"),
    (("Prod", "EU"), "a list"),
    ([], "a list"),
    ({"Prod"}, "a list"),
    ({"name": "Prod"}, "a dictionary"),
    ({}, "a dictionary"),
    (True, "a boolean (True)"),
    (False, "a boolean (False)"),
    (2024, "a number (2024)"),
    (0, "a number (0)"),
    (1.1, "a number (1.1)"),
    (2026.0, "a number (2026.0)"),
    (datetime.date(2026, 9, 29), "a date (2026-09-29)"),
    (datetime.datetime(2026, 9, 29, 10, 0), "a date and time (2026-09-29 10:00:00)"),
    (b"Prod", "a byte string"),
]

# A password for these tests only, to make real vault-encrypted values.
VAULT_TEST_PASSWORD = b"keeper-folder-vault-test-only"

_UPDATE_SIGNATURE = inspect.signature(SecretsManager.update_folder)


def _folder(uid, parent_uid, name):
    return KeeperFolder(b"k" * 32, uid, parent_uid, name)


def _tree():
    """
    A fresh copy of this folder tree, in the order that the server lists it (shared folders first):

    Infrastructure (shared)
        Databases
            Staging
            Production
                EU
                    Frankfurt
    Applications (shared)
        Staging
        Archive
    """
    return [
        _folder(SHARED_INFRA, "", "Infrastructure"),
        _folder(SHARED_APPS, "", "Applications"),
        _folder(DATABASES, SHARED_INFRA, "Databases"),
        _folder(STAGING, DATABASES, "Staging"),
        _folder(PRODUCTION, DATABASES, "Production"),
        _folder(EU, PRODUCTION, "EU"),
        _folder(FRANKFURT, EU, "Frankfurt"),
        _folder(APPS_STAGING, SHARED_APPS, "Staging"),
        _folder(ARCHIVE, SHARED_APPS, "Archive"),
    ]


def _keeper(folders):
    """
    A KeeperAnsible with a fake SDK client, built without the constructor so nothing connects.

    The client is an autospec of SecretsManager, so a call that does not fit the real SDK signature (for
    example a misspelled keyword argument) fails the test instead of passing silently.
    """
    keeper = object.__new__(KeeperAnsible)
    keeper.client = create_autospec(SecretsManager, instance=True)
    keeper.client.get_folders.return_value = folders
    return keeper


def _vaulted(*texts):
    """
    Real vault-encrypted strings of the installed ansible-core, as a playbook gives them with !vault, and a context
    manager in which they can be decrypted. ansible-core 2.19 and later use EncryptedString, which decrypts with the
    secrets of VaultSecretsContext. Earlier versions use AnsibleVaultEncryptedUnicode, which holds its own VaultLib.
    The classes are imported when the test runs, because the test framework reloads the ansible modules between
    playbook runs, and the code under test imports them from the reloaded modules too.
    """
    import ansible.parsing.vault as vault_module

    secret = vault_module.VaultSecret(VAULT_TEST_PASSWORD)
    vault = vault_module.VaultLib([("default", secret)])
    ciphertexts = [vault.encrypt(text) for text in texts]
    if hasattr(vault_module, "EncryptedString"):
        context = patch.object(vault_module.VaultSecretsContext, "_current",
                               vault_module.VaultSecretsContext(secrets=[("default", secret)]))
        return [vault_module.EncryptedString(ciphertext=c.decode()) for c in ciphertexts], context

    from ansible.parsing.yaml.objects import AnsibleVaultEncryptedUnicode

    values = []
    for ciphertext in ciphertexts:
        value = AnsibleVaultEncryptedUnicode(ciphertext)
        value.vault = vault
        values.append(value)
    return values, contextlib.nullcontext()


def _padded_message(shown):
    """The message for a new name with whitespace at the start or the end. shown is the repr() of the name."""
    return ("The new_folder_name {} has leading or trailing whitespace. Remove it. In YAML, a block scalar (| or >) "
            "keeps the newline at its end.".format(shown))


def _split_supported(message):
    """
    The text of a message before the list of supported parameters, and the names in that list as a set.
    ansible-core 2.12 gives the names in set order, and later versions sort them, so a test must not depend on
    the order of that list.
    """
    before, found, names = message.partition(SUPPORTED)
    if not found or not names.endswith("."):
        return message, None
    return before, set(names[:-1].split(", "))


def _call_names(client):
    return [c[0] for c in client.mock_calls]


def _update_arguments(client):
    """The arguments of the one update_folder call, by parameter name, whether they were positional or not."""
    args, kwargs = client.update_folder.call_args
    bound = _UPDATE_SIGNATURE.bind(None, *args, **kwargs)
    bound.apply_defaults()
    return bound.arguments


class _UpdateFolderTestCase(unittest.TestCase):

    def assert_renamed(self, keeper, folders, folder_uid, new_name):
        """The SDK got exactly one fetch and then exactly one update, with the list from that fetch."""
        self.assertEqual(_call_names(keeper.client), ["get_folders", "update_folder"])
        keeper.client.get_folders.assert_called_once_with()
        keeper.client.update_folder.assert_called_once_with(folder_uid, new_name, folders=folders)
        self.assertIs(_update_arguments(keeper.client)["folders"], folders,
                      "the SDK must get the same list object, so that it does not fetch the folders again")

    def assert_not_renamed(self, keeper):
        """The folders were read once, and nothing was sent after that."""
        keeper.client.update_folder.assert_not_called()
        keeper.client.get_folders.assert_called_once_with()
        self.assertEqual(_call_names(keeper.client), ["get_folders"])

    def assert_folder_error(self, context, message):
        self.assertIsInstance(context.exception, KeeperFolderError)
        self.assertEqual(str(context.exception), message)


class KeeperUpdateFolderAcceptanceTest(_UpdateFolderTestCase):
    """
    The acceptance criteria of keeper_update_folder, one test each, and the QA test instructions at the level
    of the KeeperAnsible method: rename a folder inside a shared folder, then run the same rename again.
    """

    def test_rename_of_existing_folder_reports_changed(self):
        """An existing folder UID and a new name: the folder is renamed, and changed is true."""
        folders = _tree()
        keeper = _keeper(folders)

        result = keeper.update_folder(STAGING, "QA")

        self.assertIs(result["changed"], True)
        self.assertEqual(result["folder_name"], "QA")
        self.assert_renamed(keeper, folders, STAGING, "QA")

    def test_same_name_reports_not_changed_and_sends_no_update(self):
        """
        A new name equal to the current name: changed is false, and no further call is made. The folders are read
        exactly once (to learn the current name), and the client gets no other call of any kind.
        """
        keeper = _keeper(_tree())

        result = keeper.update_folder(STAGING, "Staging")

        self.assertIs(result["changed"], False)
        keeper.client.update_folder.assert_not_called()
        keeper.client.get_folders.assert_called_once_with()
        self.assertEqual(keeper.client.mock_calls, [call.get_folders()])

    def test_unknown_folder_uid_fails_with_clear_error(self):
        """A folder UID that does not exist fails with a message that names the UID. No update is sent."""
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(MISSING, "QA")

        self.assert_folder_error(context, NOT_FOUND.format(MISSING))
        self.assert_not_renamed(keeper)

    def test_folder_not_shared_to_the_application_fails_with_the_same_error(self):
        """
        The SDK's get_folders returns only the folders that are shared to the KSM application. A folder that exists
        in the vault but is not shared is absent from that list, so it must fail the same way as a missing folder.
        Here the Applications shared folder and its subfolders are not shared to the application.
        """
        shared_to_app = [f for f in _tree() if f.folder_uid not in (SHARED_APPS, APPS_STAGING, ARCHIVE)]
        keeper = _keeper(shared_to_app)

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(ARCHIVE, "Old Archive")

        self.assert_folder_error(context, NOT_FOUND.format(ARCHIVE))
        self.assert_not_renamed(keeper)

    def test_rename_then_same_rename_again(self):
        """
        The QA steps: rename a folder in a shared folder (changed), then run the same task again with the same new
        name. The second run sees the new name, so it reports changed false and sends nothing.
        """
        folders = _tree()
        keeper = _keeper(folders)
        first = keeper.update_folder(STAGING, "Production Databases")
        self.assert_renamed(keeper, folders, STAGING, "Production Databases")

        # What the vault returns after the rename.
        renamed = _tree()
        next(f for f in renamed if f.folder_uid == STAGING).name = "Production Databases"
        keeper_again = _keeper(renamed)
        second = keeper_again.update_folder(STAGING, "Production Databases")

        self.assertEqual(first, {"changed": True, "folder_uid": STAGING, "folder_name": "Production Databases",
                                 "previous_folder_name": "Staging"})
        self.assertEqual(second, {"changed": False, "folder_uid": STAGING, "folder_name": "Production Databases",
                                  "previous_folder_name": "Production Databases"})
        self.assert_not_renamed(keeper_again)


class KeeperUpdateFolderRenameCallTest(_UpdateFolderTestCase):
    """How the rename reaches the SDK: one fetch, then one update_folder call with the list from that fetch."""

    def test_update_gets_uid_name_and_the_same_folder_list(self):
        """
        The SDK's update_folder fetches all folders again when folders is not given. The module already has the
        list, so it must pass that same list object, and there must be no second get_folders call.
        """
        folders = _tree()
        keeper = _keeper(folders)

        keeper.update_folder(STAGING, "QA")

        self.assertEqual(keeper.client.mock_calls, [call.get_folders(), call.update_folder(STAGING, "QA",
                                                                                            folders=folders)])
        arguments = _update_arguments(keeper.client)
        self.assertEqual(arguments["folder_uid"], STAGING)
        self.assertEqual(arguments["folder_name"], "QA")
        self.assertIs(arguments["folders"], folders)

    def test_folder_list_is_passed_complete_and_unchanged(self):
        """The SDK looks up the folder key in the list, so the list must reach it with every folder, in order."""
        folders = _tree()
        expected = [(f.folder_uid, f.parent_uid, f.name) for f in folders]
        keeper = _keeper(folders)

        keeper.update_folder(FRANKFURT, "Berlin")

        passed = _update_arguments(keeper.client)["folders"]
        self.assertEqual([(f.folder_uid, f.parent_uid, f.name) for f in passed], expected)

    def test_only_the_named_folder_is_renamed(self):
        """Two folders are named Staging. The UID picks one; the other is never sent."""
        folders = _tree()
        keeper = _keeper(folders)

        keeper.update_folder(APPS_STAGING, "Pre-Production")

        self.assert_renamed(keeper, folders, APPS_STAGING, "Pre-Production")

    def test_rename_of_shared_folder(self):
        """A shared folder (top level, parent_uid "") can be renamed like any other folder."""
        folders = _tree()
        keeper = _keeper(folders)

        result = keeper.update_folder(SHARED_INFRA, "Infrastructure 2026")

        self.assertEqual(result, {"changed": True, "folder_uid": SHARED_INFRA, "folder_name": "Infrastructure 2026",
                                  "previous_folder_name": "Infrastructure"})
        self.assert_renamed(keeper, folders, SHARED_INFRA, "Infrastructure 2026")

    def test_rename_of_shared_folder_with_none_parent(self):
        """A shared folder whose parent_uid is None, not "", is still found and renamed."""
        folders = [_folder(SHARED_INFRA, None, "Infrastructure"), _folder(DATABASES, SHARED_INFRA, "Databases")]
        keeper = _keeper(folders)

        result = keeper.update_folder(SHARED_INFRA, "Infra")

        self.assertIs(result["changed"], True)
        self.assert_renamed(keeper, folders, SHARED_INFRA, "Infra")

    def test_rename_of_deep_subfolder(self):
        """A folder four levels below its shared folder is found by UID alone and renamed."""
        folders = _tree()
        keeper = _keeper(folders)

        result = keeper.update_folder(FRANKFURT, "Berlin")

        self.assertEqual(result, {"changed": True, "folder_uid": FRANKFURT, "folder_name": "Berlin",
                                  "previous_folder_name": "Frankfurt"})
        self.assert_renamed(keeper, folders, FRANKFURT, "Berlin")

    def test_rename_of_folder_with_subfolders(self):
        """A rename changes only the name, so a folder that has subfolders can be renamed too."""
        folders = _tree()
        keeper = _keeper(folders)

        keeper.update_folder(DATABASES, "Data Stores")

        self.assert_renamed(keeper, folders, DATABASES, "Data Stores")

    def test_rename_of_folder_with_empty_current_name(self):
        """The SDK gives "" as the name of a folder that has no name data. A real name is a rename."""
        folders = _tree() + [_folder("NAMELESS_UID", DATABASES, "")]
        keeper = _keeper(folders)

        result = keeper.update_folder("NAMELESS_UID", "Named")

        self.assertEqual(result, {"changed": True, "folder_uid": "NAMELESS_UID", "folder_name": "Named",
                                  "previous_folder_name": ""})
        self.assert_renamed(keeper, folders, "NAMELESS_UID", "Named")


class KeeperUpdateFolderResultTest(_UpdateFolderTestCase):
    """The result dictionary has exactly these keys: changed, folder_uid, folder_name, previous_folder_name."""

    def test_result_of_a_rename(self):
        """folder_name is the name after the task; previous_folder_name is the name before it."""
        result = _keeper(_tree()).update_folder(STAGING, "QA")

        self.assertEqual(result, {"changed": True, "folder_uid": STAGING, "folder_name": "QA",
                                  "previous_folder_name": "Staging"})
        self.assertIs(result["changed"], True)

    def test_result_of_a_no_op(self):
        """With no rename, folder_name and previous_folder_name are both the current name."""
        result = _keeper(_tree()).update_folder(STAGING, "Staging")

        self.assertEqual(result, {"changed": False, "folder_uid": STAGING, "folder_name": "Staging",
                                  "previous_folder_name": "Staging"})
        self.assertIs(result["changed"], False)

    def test_result_in_check_mode(self):
        """Check mode reports what a real run would do: the same dictionary, key for key."""
        check = _keeper(_tree()).update_folder(STAGING, "QA", check_mode=True)
        real = _keeper(_tree()).update_folder(STAGING, "QA")

        self.assertEqual(check, {"changed": True, "folder_uid": STAGING, "folder_name": "QA",
                                 "previous_folder_name": "Staging"})
        self.assertEqual(check, real)

    def test_result_of_a_no_op_in_check_mode(self):
        check = _keeper(_tree()).update_folder(STAGING, "Staging", check_mode=True)

        self.assertEqual(check, {"changed": False, "folder_uid": STAGING, "folder_name": "Staging",
                                 "previous_folder_name": "Staging"})

    def test_result_values_are_strings(self):
        """
        The option check lets only strings through. Called directly with an int, the method still sends and returns
        a str, so the SDK never gets a JSON number as a folder name.
        """
        folders = _tree() + [_folder("YEAR_UID", DATABASES, "2025")]
        keeper = _keeper(folders)

        result = keeper.update_folder("YEAR_UID", 2026)

        self.assertEqual(result, {"changed": True, "folder_uid": "YEAR_UID", "folder_name": "2026",
                                  "previous_folder_name": "2025"})
        self.assertIsInstance(result["folder_name"], str)
        self.assertIsInstance(_update_arguments(keeper.client)["folder_name"], str)
        self.assert_renamed(keeper, folders, "YEAR_UID", "2026")

    def test_int_name_equal_to_the_current_name_is_a_no_op(self):
        """Called directly with the int 2025, the method compares the str "2025", the current name: a no-op."""
        keeper = _keeper(_tree() + [_folder("YEAR_UID", DATABASES, "2025")])

        result = keeper.update_folder("YEAR_UID", 2025)

        self.assertIs(result["changed"], False)
        self.assert_not_renamed(keeper)


class KeeperUpdateFolderNameComparisonTest(_UpdateFolderTestCase):
    """
    The current name and the new name are compared exactly: case, whitespace inside the name, and code points all
    count. A new name with whitespace at the start or the end fails (see KeeperUpdateFolderPaddedNameTest).
    """

    def test_case_change_is_a_rename(self):
        """keeper_get_folder matches names case-sensitively, so "Staging" to "staging" is a real change."""
        for new_name in ("staging", "STAGING", "sTAGING"):
            with self.subTest(new_name=new_name):
                folders = _tree()
                keeper = _keeper(folders)

                result = keeper.update_folder(STAGING, new_name)

                self.assertIs(result["changed"], True)
                self.assertEqual(result["previous_folder_name"], "Staging")
                self.assert_renamed(keeper, folders, STAGING, new_name)

    def test_whitespace_inside_the_name_is_a_rename(self):
        """
        Whitespace inside a name is part of the name, and the names are compared exactly: one space or two, a space
        or a tab, and a space or a newline are different names. The new name is sent as given.
        """
        cases = [
            ("A B", "A  B"),
            ("A B", "A\tB"),
            ("Prod EU", "Prod\nEU"),
            ("Prod\r\nEU", "Prod\nEU"),
            ("AB", "A B"),
        ]
        for current, new_name in cases:
            with self.subTest(current=current, new_name=new_name):
                folders = [_folder(SHARED_INFRA, "", "Infrastructure"), _folder("A_UID", SHARED_INFRA, current)]
                keeper = _keeper(folders)

                result = keeper.update_folder("A_UID", new_name)

                self.assertEqual(result, {"changed": True, "folder_uid": "A_UID", "folder_name": new_name,
                                          "previous_folder_name": current})
                self.assert_renamed(keeper, folders, "A_UID", new_name)

    def test_padded_current_name_can_be_renamed_to_a_clean_name(self):
        """
        Only the new name is checked for whitespace at the start or the end. A folder whose current name has it (a
        name made in the vault, or by an earlier version of this module) can be renamed to the clean name.
        """
        for current in ("A ", " A", "A\t", "\tA", "A\n", "A\r\n"):
            with self.subTest(current=current):
                folders = [_folder(SHARED_INFRA, "", "Infrastructure"), _folder("A_UID", SHARED_INFRA, current)]
                keeper = _keeper(folders)

                result = keeper.update_folder("A_UID", "A")

                self.assertEqual(result, {"changed": True, "folder_uid": "A_UID", "folder_name": "A",
                                          "previous_folder_name": current})
                self.assert_renamed(keeper, folders, "A_UID", "A")

    def test_unicode_name_is_sent_unchanged(self):
        folders = _tree()
        keeper = _keeper(folders)
        new_name = "Datenbanken \u00e4\u00f6\u00fc\u00df \u6570\u636e\u5e93 \u0411\u0430\u0437\u044b \U0001F512"

        result = keeper.update_folder(STAGING, new_name)

        self.assertEqual(result["folder_name"], new_name)
        self.assert_renamed(keeper, folders, STAGING, new_name)

    def test_same_unicode_name_is_a_no_op(self):
        keeper = _keeper([_folder(SHARED_INFRA, "", "Infrastructure"),
                          _folder("U_UID", SHARED_INFRA, "\u6570\u636e\u5e93 \U0001F512")])

        result = keeper.update_folder("U_UID", "\u6570\u636e\u5e93 \U0001F512")

        self.assertIs(result["changed"], False)
        self.assert_not_renamed(keeper)

    def test_unicode_normalization_forms_are_different_names(self):
        """
        "Cafe" with a precomposed e-acute (one code point, NFC) and "Cafe" with a combining acute accent (two code
        points, NFD) look the same but are different strings.
        The comparison is exact, so the name is sent. The module does not normalize names.
        """
        folders = [_folder(SHARED_INFRA, "", "Infrastructure"), _folder("C_UID", SHARED_INFRA, "Caf\u00e9")]
        keeper = _keeper(folders)

        result = keeper.update_folder("C_UID", "Cafe\u0301")

        self.assertIs(result["changed"], True)
        self.assert_renamed(keeper, folders, "C_UID", "Cafe\u0301")

    def test_long_name_is_sent_in_full(self):
        """The module does not shorten a name. A limit, if any, belongs to the server."""
        folders = _tree()
        keeper = _keeper(folders)
        new_name = "Long folder name " + "x" * 4096

        result = keeper.update_folder(STAGING, new_name)

        self.assertEqual(len(result["folder_name"]), len(new_name))
        self.assert_renamed(keeper, folders, STAGING, new_name)

    def test_name_with_slash_is_a_plain_name(self):
        """A "/" in a new name is part of the name. It does not move the folder or create a path."""
        folders = _tree()
        keeper = _keeper(folders)

        result = keeper.update_folder(STAGING, "Databases/Legacy")

        self.assertEqual(result, {"changed": True, "folder_uid": STAGING, "folder_name": "Databases/Legacy",
                                  "previous_folder_name": "Staging"})
        self.assert_renamed(keeper, folders, STAGING, "Databases/Legacy")

    def test_same_name_with_slash_is_a_no_op(self):
        keeper = _keeper([_folder(SHARED_INFRA, "", "Infrastructure"), _folder("S_UID", SHARED_INFRA, "A/B")])

        result = keeper.update_folder("S_UID", "A/B")

        self.assertIs(result["changed"], False)
        self.assert_not_renamed(keeper)

    def test_other_unusual_names_are_sent_unchanged(self):
        """Quotes, template-like braces, inner newlines, and leading dots are all plain characters of a name."""
        for new_name in ('He said "hi"', "{{ not_a_template }}", "Line 1\nLine 2", ".hidden", "-", "0"):
            with self.subTest(new_name=new_name):
                folders = _tree()
                keeper = _keeper(folders)

                result = keeper.update_folder(STAGING, new_name)

                self.assertEqual(result["folder_name"], new_name)
                self.assert_renamed(keeper, folders, STAGING, new_name)


class KeeperUpdateFolderPaddedNameTest(_UpdateFolderTestCase):
    """
    A new name with whitespace at the start or the end fails before any SDK call, even before the folders are read:
    a later lookup of the clean name would not find the folder. The message shows the name with repr(), so that the
    whitespace is visible. Whitespace inside the name is allowed (see KeeperUpdateFolderNameComparisonTest).
    """

    def assert_fails_before_any_sdk_call(self, new_name, shown, folder_uid=STAGING, check_mode=False, folders=None):
        keeper = _keeper(_tree() if folders is None else folders)

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(folder_uid, new_name, check_mode=check_mode)

        self.assert_folder_error(context, _padded_message(shown))
        self.assertEqual(keeper.client.mock_calls, [], "a padded name must fail before get_folders")

    def test_each_kind_of_padding_fails_with_the_exact_message(self):
        cases = [
            (" Production", "' Production'"),
            ("Production ", "'Production '"),
            ("  Production  ", "'  Production  '"),
            ("\tProduction", "'\\tProduction'"),
            ("Production\t", "'Production\\t'"),
            ("Production\n", "'Production\\n'"),
            ("\nProduction", "'\\nProduction'"),
            ("Production\r", "'Production\\r'"),
            ("Production\r\n", "'Production\\r\\n'"),
            ("Production\u00a0", "'Production\\xa0'"),
            ("Bob's folder ", '"Bob\'s folder "'),
        ]
        for new_name, shown in cases:
            with self.subTest(new_name=new_name):
                self.assert_fails_before_any_sdk_call(new_name, shown)

    def test_yaml_block_scalar_fails_and_strip_chomping_works(self):
        """
        A block scalar (|) or a folded scalar (>) keeps the newline at its end, so the name has one. The strip
        chomping indicator (|-) removes it, and that name is renamed.
        """
        from ansible.parsing.yaml.loader import AnsibleLoader

        for text in ("new_folder_name: |\n  Production\n", "new_folder_name: >\n  Production\n"):
            with self.subTest(text=text):
                value = AnsibleLoader(text).get_single_data()["new_folder_name"]
                self.assertEqual(value, "Production\n")

                self.assert_fails_before_any_sdk_call(value, "'Production\\n'")

        value = AnsibleLoader("new_folder_name: |-\n  Production\n").get_single_data()["new_folder_name"]
        folders = _tree()
        keeper = _keeper(folders)
        keeper.update_folder(STAGING, value)
        self.assert_renamed(keeper, folders, STAGING, "Production")

    def test_padded_name_fails_before_the_folder_lookup(self):
        """For a folder that does not exist, the padding is reported, not "not found": the check comes first."""
        self.assert_fails_before_any_sdk_call("Production\n", "'Production\\n'", folder_uid=MISSING)

    def test_padded_name_fails_in_check_mode(self):
        self.assert_fails_before_any_sdk_call("Production ", "'Production '", check_mode=True)

    def test_padded_name_fails_even_when_the_folder_already_has_it(self):
        """
        The check comes before the folders are read, so a padded new name fails even if the folder already has
        exactly that name. Without the padding, the task then renames the folder to the clean name.
        """
        folders = [_folder(SHARED_INFRA, "", "Infrastructure"), _folder("A_UID", SHARED_INFRA, "A ")]

        self.assert_fails_before_any_sdk_call("A ", "'A '", folder_uid="A_UID", folders=folders)

    def test_whitespace_only_is_blank_not_padded(self):
        """A name of only whitespace is reported as blank, not as padded."""
        for new_name in (" ", "\n", " \t\r\n "):
            with self.subTest(new_name=new_name):
                keeper = _keeper(_tree())

                with self.assertRaises(KeeperFolderError) as context:
                    keeper.update_folder(STAGING, new_name)

                self.assert_folder_error(context, BLANK_NAME)
                self.assertEqual(keeper.client.mock_calls, [])


class KeeperUpdateFolderInputValidationTest(_UpdateFolderTestCase):
    """A blank name or a blank or padded UID fails before the module talks to the SDK at all."""

    def test_blank_new_folder_name_fails_before_any_sdk_call(self):
        """
        A blank name usually comes from an empty template variable. It must fail, and it must fail before
        get_folders, so a broken playbook makes no request.
        """
        for new_name in (None, "", " ", "   ", "\t", "\n", " \t\r\n ", "\u00a0", "\u3000"):
            with self.subTest(new_name=new_name):
                keeper = _keeper(_tree())

                with self.assertRaises(KeeperFolderError) as context:
                    keeper.update_folder(STAGING, new_name)

                self.assert_folder_error(context, BLANK_NAME)
                self.assertEqual(keeper.client.mock_calls, [])

    def test_blank_new_folder_name_fails_for_missing_folder_too(self):
        """The name check does not depend on the folder: a blank name fails even for a UID that does not exist."""
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(MISSING, "  ")

        self.assert_folder_error(context, BLANK_NAME)
        self.assertEqual(keeper.client.mock_calls, [])

    def test_blank_folder_uid_fails_before_any_sdk_call(self):
        for folder_uid in (None, "", " ", "   ", "\t", "\n"):
            with self.subTest(folder_uid=folder_uid):
                keeper = _keeper(_tree())

                with self.assertRaises(KeeperFolderError) as context:
                    keeper.update_folder(folder_uid, "QA")

                self.assert_folder_error(context, BLANK_UID)
                self.assertEqual(keeper.client.mock_calls, [])

    def test_padded_folder_uid_fails_instead_of_not_found(self):
        """
        A UID with a leading or trailing space or newline (for example from a registered stdout) must fail with
        a message that shows the value, not with "not found", and it must not be stripped and used.
        """
        cases = [
            (" ABC", "The folder_uid ' ABC' has leading or trailing whitespace."),
            ("ABC\n", "The folder_uid 'ABC\\n' has leading or trailing whitespace."),
            ("\tABC", "The folder_uid '\\tABC' has leading or trailing whitespace."),
            ("ABC ", "The folder_uid 'ABC ' has leading or trailing whitespace."),
        ]
        for folder_uid, message in cases:
            with self.subTest(folder_uid=folder_uid):
                keeper = _keeper(_tree() + [_folder("ABC", SHARED_INFRA, "Old")])

                with self.assertRaises(KeeperFolderError) as context:
                    keeper.update_folder(folder_uid, "QA")

                self.assert_folder_error(context, message)
                self.assertEqual(keeper.client.mock_calls, [])

    def test_padded_uid_of_an_existing_folder_is_not_renamed(self):
        """The UID without the padding exists. It must still fail, and the folder must not be renamed."""
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(" " + STAGING, "QA")

        self.assert_folder_error(context, "The folder_uid ' STAGING_UID' has leading or trailing whitespace.")
        self.assertEqual(keeper.client.mock_calls, [])

    def test_blank_uid_and_blank_name_fail_before_any_sdk_call(self):
        """
        With both blank, one of the two blank errors is raised. Which check runs first is not part of the contract.
        """
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder("", "")

        self.assertIn(str(context.exception), (BLANK_UID, BLANK_NAME))
        self.assertEqual(keeper.client.mock_calls, [])

    def test_uid_match_is_case_sensitive(self):
        """Keeper UIDs are case-sensitive. A UID that differs only in case is a different folder, so it is not found."""
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(STAGING.lower(), "QA")

        self.assert_folder_error(context, NOT_FOUND.format(STAGING.lower()))
        self.assert_not_renamed(keeper)

    def test_folder_name_is_not_a_uid(self):
        """The folder_uid option takes a UID. A folder's name given as the UID is not found."""
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder("Staging", "QA")

        self.assert_folder_error(context, NOT_FOUND.format("Staging"))
        self.assert_not_renamed(keeper)


class KeeperUpdateFolderNotFoundTest(_UpdateFolderTestCase):
    """A folder that is not in the get_folders list fails, and update_folder is never called."""

    def test_missing_folder_in_a_full_list(self):
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(MISSING, "QA")

        self.assert_folder_error(context, NOT_FOUND.format(MISSING))
        self.assert_not_renamed(keeper)

    def test_missing_folder_with_no_folders_shared(self):
        """An application with no folders shared to it gets an empty list, and the same clear error."""
        keeper = _keeper([])

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(STAGING, "QA")

        self.assert_folder_error(context, NOT_FOUND.format(STAGING))
        self.assert_not_renamed(keeper)

    def test_missing_folder_when_sdk_returns_none(self):
        """If the SDK returns None instead of a list, the result is the not-found error, not a TypeError."""
        keeper = _keeper(None)

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(STAGING, "QA")

        self.assert_folder_error(context, NOT_FOUND.format(STAGING))
        self.assert_not_renamed(keeper)

    def test_missing_folder_is_not_left_to_the_sdk(self):
        """
        The SDK's own error for a missing folder is "Unable to update folder - folder key for ... not found". The
        module must find the problem itself and give its clearer message, so update_folder is never called, even
        when the SDK would raise.
        """
        keeper = _keeper(_tree())
        keeper.client.update_folder.side_effect = KeeperError(
            "Unable to update folder - folder key for {} not found".format(MISSING))

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(MISSING, "QA")

        self.assert_folder_error(context, NOT_FOUND.format(MISSING))
        self.assert_not_renamed(keeper)

    def test_missing_folder_in_check_mode_still_fails(self):
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(MISSING, "QA", check_mode=True)

        self.assert_folder_error(context, NOT_FOUND.format(MISSING))
        self.assert_not_renamed(keeper)


class KeeperUpdateFolderSameNameWarningTest(_UpdateFolderTestCase):
    """
    Keeper allows two folders with the same name in one parent, so a rename into a name that a sibling already has
    is allowed. But a later lookup of that name by keeper_get_folder fails, so the module shows a warning.
    """

    def _rename(self, folders, folder_uid, new_name, check_mode=False):
        keeper = _keeper(folders)
        with patch("keeper_secrets_manager_ansible.display.warning") as warning:
            result = keeper.update_folder(folder_uid, new_name, check_mode=check_mode)
        return keeper, result, warning

    def test_sibling_with_the_new_name_warns_and_still_renames(self):
        folders = _tree()

        keeper, result, warning = self._rename(folders, STAGING, "Production")

        warning.assert_called_once()
        message = warning.call_args[0][0]
        self.assertIn(STAGING_LABEL, message, "the warning must name the folder that is renamed")
        self.assertIn('"Production"', message, "the warning must show the new name")
        self.assertIn(PRODUCTION, message, "the warning must name the folder that already has the name")
        self.assertIs(result["changed"], True)
        self.assert_renamed(keeper, folders, STAGING, "Production")

    def test_two_siblings_with_the_new_name_give_one_warning_with_both(self):
        folders = _tree() + [_folder("QA_1_UID", DATABASES, "QA"), _folder("QA_2_UID", DATABASES, "QA")]

        keeper, result, warning = self._rename(folders, STAGING, "QA")

        warning.assert_called_once()
        message = warning.call_args[0][0]
        self.assertIn("QA_1_UID", message)
        self.assertIn("QA_2_UID", message)
        self.assert_renamed(keeper, folders, STAGING, "QA")

    def test_same_name_in_a_different_parent_does_not_warn(self):
        """Archive is in the Applications shared folder, not in Databases, so a lookup stays unique."""
        folders = _tree()

        keeper, result, warning = self._rename(folders, STAGING, "Archive")

        warning.assert_not_called()
        self.assert_renamed(keeper, folders, STAGING, "Archive")

    def test_same_name_elsewhere_in_the_tree_does_not_warn(self):
        """The parent, a child of a sibling, and a shared folder are not siblings of Staging."""
        for new_name in ("Databases", "EU", "Frankfurt", "Infrastructure", "Applications"):
            with self.subTest(new_name=new_name):
                folders = _tree()

                keeper, result, warning = self._rename(folders, STAGING, new_name)

                warning.assert_not_called()
                self.assert_renamed(keeper, folders, STAGING, new_name)

    def test_same_name_in_own_subfolder_does_not_warn(self):
        """A child with the new name is not a sibling: its lookup path is different."""
        folders = _tree()

        keeper, result, warning = self._rename(folders, PRODUCTION, "EU")

        warning.assert_not_called()
        self.assert_renamed(keeper, folders, PRODUCTION, "EU")

    def test_sibling_that_differs_only_in_case_does_not_warn(self):
        """Lookups are case-sensitive, so "production" next to "Production" is still unique."""
        folders = _tree()

        keeper, result, warning = self._rename(folders, STAGING, "production")

        warning.assert_not_called()
        self.assert_renamed(keeper, folders, STAGING, "production")

    def test_sibling_that_differs_only_in_whitespace_does_not_warn(self):
        """
        Names are compared exactly. A sibling named "Production " (an old name with a trailing space) or "Prod  EU"
        (two spaces inside) does not have the new name "Production" or "Prod EU", so there is no warning.
        """
        for new_name in ("Production", "Prod EU"):
            with self.subTest(new_name=new_name):
                folders = [
                    _folder(SHARED_INFRA, "", "Infrastructure"),
                    _folder(DATABASES, SHARED_INFRA, "Databases"),
                    _folder(STAGING, DATABASES, "Staging"),
                    _folder("PADDED_UID", DATABASES, "Production "),
                    _folder("DOUBLE_SPACE_UID", DATABASES, "Prod  EU"),
                ]

                keeper, result, warning = self._rename(folders, STAGING, new_name)

                warning.assert_not_called()
                self.assert_renamed(keeper, folders, STAGING, new_name)

    def test_folder_that_already_has_the_name_does_not_warn(self):
        """The only folder with the name is the folder itself: a no-op, with no warning."""
        keeper, result, warning = self._rename(_tree(), STAGING, "Staging")

        warning.assert_not_called()
        self.assertIs(result["changed"], False)
        self.assert_not_renamed(keeper)

    def test_duplicate_entry_of_the_folder_itself_does_not_warn(self):
        """
        If the server lists the same folder twice (malformed data, here with the new name in the second entry), the
        second entry is still the folder itself, not a sibling, so it must not cause a warning.
        """
        folders = _tree() + [_folder(STAGING, DATABASES, "QA")]

        keeper, result, warning = self._rename(folders, STAGING, "QA")

        warning.assert_not_called()
        self.assertIs(result["changed"], True)
        self.assert_renamed(keeper, folders, STAGING, "QA")

    def test_other_same_named_folder_in_other_parent_with_no_op_does_not_warn(self):
        """Applications/Staging keeps its name; Infrastructure/Databases/Staging is elsewhere. No warning."""
        keeper, result, warning = self._rename(_tree(), APPS_STAGING, "Staging")

        warning.assert_not_called()
        self.assertIs(result["changed"], False)

    def test_rename_without_any_same_name_does_not_warn(self):
        folders = _tree()

        keeper, result, warning = self._rename(folders, STAGING, "QA")

        warning.assert_not_called()
        self.assert_renamed(keeper, folders, STAGING, "QA")

    def test_shared_folder_with_the_name_of_another_shared_folder_warns(self):
        """For a shared folder, the siblings are the other shared folders of the application (the top level)."""
        folders = _tree()

        keeper, result, warning = self._rename(folders, SHARED_INFRA, "Applications")

        warning.assert_called_once()
        message = warning.call_args[0][0]
        self.assertIn('"Infrastructure" (UID SHARED_INFRA_UID)', message)
        self.assertIn(SHARED_APPS, message)
        self.assert_renamed(keeper, folders, SHARED_INFRA, "Applications")

    def test_shared_folder_with_the_name_of_a_subfolder_does_not_warn(self):
        """Subfolders named Staging exist, but none of them is at the top level."""
        folders = _tree()

        keeper, result, warning = self._rename(folders, SHARED_INFRA, "Staging")

        warning.assert_not_called()
        self.assert_renamed(keeper, folders, SHARED_INFRA, "Staging")

    def test_top_level_siblings_with_mixed_empty_and_none_parent_warn(self):
        """A shared folder with parent_uid None and one with parent_uid "" are both at the top level."""
        folders = [_folder(SHARED_INFRA, "", "Infrastructure"), _folder(SHARED_APPS, None, "Applications")]

        keeper, result, warning = self._rename(folders, SHARED_INFRA, "Applications")

        warning.assert_called_once()
        self.assertIn(SHARED_APPS, warning.call_args[0][0])
        self.assert_renamed(keeper, folders, SHARED_INFRA, "Applications")

    def test_deep_subfolder_sibling_warns(self):
        folders = _tree() + [_folder("BERLIN_UID", EU, "Berlin")]

        keeper, result, warning = self._rename(folders, FRANKFURT, "Berlin")

        warning.assert_called_once()
        message = warning.call_args[0][0]
        self.assertIn('"Infrastructure/Databases/Production/EU/Frankfurt" (UID FRANKFURT_UID)', message)
        self.assertIn("BERLIN_UID", message)
        self.assert_renamed(keeper, folders, FRANKFURT, "Berlin")

    def test_warning_is_also_shown_in_check_mode(self):
        """Check mode runs the same checks, so the warning is shown, but nothing is sent."""
        folders = _tree()

        keeper, result, warning = self._rename(folders, STAGING, "Production", check_mode=True)

        warning.assert_called_once()
        self.assertIn(PRODUCTION, warning.call_args[0][0])
        self.assertIs(result["changed"], True)
        self.assert_not_renamed(keeper)


class KeeperUpdateFolderCheckModeTest(_UpdateFolderTestCase):
    """In check mode the module runs every check and gives the same result, but never calls update_folder."""

    def test_check_mode_rename_is_reported_but_not_sent(self):
        keeper = _keeper(_tree())

        result = keeper.update_folder(STAGING, "QA", check_mode=True)

        self.assertEqual(result, {"changed": True, "folder_uid": STAGING, "folder_name": "QA",
                                  "previous_folder_name": "Staging"})
        self.assert_not_renamed(keeper)

    def test_check_mode_no_op_reports_not_changed(self):
        keeper = _keeper(_tree())

        result = keeper.update_folder(STAGING, "Staging", check_mode=True)

        self.assertIs(result["changed"], False)
        self.assert_not_renamed(keeper)

    def test_check_mode_missing_folder_still_fails(self):
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(MISSING, "QA", check_mode=True)

        self.assert_folder_error(context, NOT_FOUND.format(MISSING))
        self.assert_not_renamed(keeper)

    def test_check_mode_blank_name_still_fails(self):
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(STAGING, " ", check_mode=True)

        self.assert_folder_error(context, BLANK_NAME)
        self.assertEqual(keeper.client.mock_calls, [])

    def test_check_mode_padded_uid_still_fails(self):
        keeper = _keeper(_tree())

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(STAGING + "\n", "QA", check_mode=True)

        self.assert_folder_error(context, "The folder_uid 'STAGING_UID\\n' has leading or trailing whitespace.")
        self.assertEqual(keeper.client.mock_calls, [])

    def test_check_mode_does_not_hide_a_get_folders_failure(self):
        """Check mode must still read the folders, so a connection problem shows in a dry run."""
        keeper = _keeper(_tree())
        keeper.client.get_folders.side_effect = KeeperError("throttled")

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(STAGING, "QA", check_mode=True)

        self.assert_folder_error(context, "Cannot get folders: throttled")
        keeper.client.update_folder.assert_not_called()

    def test_check_mode_false_sends_the_update(self):
        """The default, and an explicit False, rename for real."""
        for kwargs in ({}, {"check_mode": False}):
            with self.subTest(kwargs=kwargs):
                folders = _tree()
                keeper = _keeper(folders)

                keeper.update_folder(STAGING, "QA", **kwargs)

                self.assert_renamed(keeper, folders, STAGING, "QA")


class KeeperUpdateFolderSdkErrorTest(_UpdateFolderTestCase):
    """SDK exceptions become a KeeperFolderError with a message that says what failed, and for which folder."""

    def test_get_folders_failure(self):
        for error in (KeeperError("throttled"), Exception("connection reset"), ValueError("bad response")):
            with self.subTest(error=error):
                keeper = _keeper(_tree())
                keeper.client.get_folders.side_effect = error

                with self.assertRaises(KeeperFolderError) as context:
                    keeper.update_folder(STAGING, "QA")

                self.assert_folder_error(context, "Cannot get folders: {}".format(error))
                keeper.client.update_folder.assert_not_called()

    def test_update_folder_failure_names_the_folder_path_and_uid(self):
        folders = _tree()
        keeper = _keeper(folders)
        keeper.client.update_folder.side_effect = KeeperError("access_denied")

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(STAGING, "QA")

        self.assert_folder_error(context, "Cannot rename the folder {}: access_denied".format(STAGING_LABEL))
        self.assert_renamed(keeper, folders, STAGING, "QA")

    def test_update_folder_failure_for_a_shared_folder(self):
        keeper = _keeper(_tree())
        keeper.client.update_folder.side_effect = KeeperError("access_denied")

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(SHARED_INFRA, "Infra")

        self.assert_folder_error(context, 'Cannot rename the folder "Infrastructure" (UID SHARED_INFRA_UID): '
                                          'access_denied')

    def test_update_folder_failure_for_a_deep_subfolder(self):
        keeper = _keeper(_tree())
        keeper.client.update_folder.side_effect = Exception("Error: 500")

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(FRANKFURT, "Berlin")

        self.assert_folder_error(context, 'Cannot rename the folder "Infrastructure/Databases/Production/EU/Frankfurt" '
                                          '(UID FRANKFURT_UID): Error: 500')

    def test_update_folder_sdk_key_error_is_wrapped(self):
        """The SDK's own "folder key not found" error for a folder that is listed but has no key is wrapped too."""
        keeper = _keeper(_tree())
        keeper.client.update_folder.side_effect = KeeperError(
            "Unable to update folder - folder key for STAGING_UID not found")

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder(STAGING, "QA")

        self.assert_folder_error(context, "Cannot rename the folder {}: Unable to update folder - folder key for "
                                          "STAGING_UID not found".format(STAGING_LABEL))

    def test_update_folder_is_not_retried_after_a_failure(self):
        keeper = _keeper(_tree())
        keeper.client.update_folder.side_effect = KeeperError("access_denied")

        with self.assertRaises(KeeperFolderError):
            keeper.update_folder(STAGING, "QA")

        self.assertEqual(_call_names(keeper.client), ["get_folders", "update_folder"])


class KeeperUpdateFolderMalformedDataTest(_UpdateFolderTestCase):
    """
    Folder data that the server should never send (a missing parent, a cycle in the parent chain) must not hang or
    crash the module. The folder path in a message is then only as long as the chain that can be followed.
    """

    def _run_with_time_limit(self, func):
        # A parent-chain cycle that is not detected loops forever. Run the call in a thread, so such a loop fails
        # this test instead of hanging the whole test run. join() returns as soon as the call ends.
        outcome = {}

        def target():
            try:
                outcome["result"] = func()
            except Exception as err:
                outcome["error"] = err

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(30)
        self.assertFalse(thread.is_alive(), "the call did not end; the parent-chain walk loops")
        return outcome

    def test_folder_with_missing_parent_is_renamed(self):
        """The SDK needs only the folder's own key, so an orphan folder can be renamed."""
        folders = [_folder(SHARED_INFRA, "", "Infrastructure"), _folder("ORPHAN_UID", "GONE_UID", "Orphan")]
        keeper = _keeper(folders)

        outcome = self._run_with_time_limit(lambda: keeper.update_folder("ORPHAN_UID", "Adopted"))

        self.assertEqual(outcome.get("result"), {"changed": True, "folder_uid": "ORPHAN_UID", "folder_name": "Adopted",
                                                 "previous_folder_name": "Orphan"})
        self.assert_renamed(keeper, folders, "ORPHAN_UID", "Adopted")

    def test_error_label_of_folder_with_missing_parent(self):
        keeper = _keeper([_folder(SHARED_INFRA, "", "Infrastructure"), _folder("ORPHAN_UID", "GONE_UID", "Orphan")])
        keeper.client.update_folder.side_effect = KeeperError("access_denied")

        outcome = self._run_with_time_limit(lambda: keeper.update_folder("ORPHAN_UID", "Adopted"))

        self.assertIsInstance(outcome.get("error"), KeeperFolderError)
        self.assertEqual(str(outcome["error"]), 'Cannot rename the folder "Orphan" (UID ORPHAN_UID): access_denied')

    def test_parent_cycle_does_not_hang_the_error_message(self):
        folders = [_folder("A_UID", "B_UID", "A"), _folder("B_UID", "A_UID", "B")]
        keeper = _keeper(folders)
        keeper.client.update_folder.side_effect = KeeperError("access_denied")

        outcome = self._run_with_time_limit(lambda: keeper.update_folder("A_UID", "C"))

        self.assertIsInstance(outcome.get("error"), KeeperFolderError)
        message = str(outcome["error"])
        self.assertTrue(message.startswith("Cannot rename the folder "), message)
        self.assertIn("(UID A_UID): access_denied", message)

    def test_parent_cycle_does_not_hang_the_warning(self):
        folders = [_folder("A_UID", "B_UID", "A"), _folder("B_UID", "A_UID", "B"), _folder("C_UID", "B_UID", "C")]
        keeper = _keeper(folders)

        with patch("keeper_secrets_manager_ansible.display.warning") as warning:
            outcome = self._run_with_time_limit(lambda: keeper.update_folder("A_UID", "C"))

        self.assertIs(outcome.get("result", {}).get("changed"), True, outcome)
        warning.assert_called_once()
        self.assertIn("C_UID", warning.call_args[0][0])


class KeeperUpdateFolderMessageQuotingTest(_UpdateFolderTestCase):
    """
    Folder names in messages are JSON-quoted, so a stray newline, tab, backslash, or double quote from a template or a
    file shows as an escape, and cannot make a message look like a different name. Other characters, also non-ASCII
    ones, are shown as they are.
    """

    def _warning_for(self, folders, folder_uid, new_name):
        keeper = _keeper(folders)
        with patch("keeper_secrets_manager_ansible.display.warning") as warning:
            keeper.update_folder(folder_uid, new_name)
        warning.assert_called_once()
        self.assert_renamed(keeper, folders, folder_uid, new_name)
        return warning.call_args[0][0]

    def test_whole_warning_text(self):
        """The full text of the same-name warning, so that any change of the wording is seen."""
        message = self._warning_for(_tree(), STAGING, "Production")

        self.assertEqual(message, 'The parent of the folder "Infrastructure/Databases/Staging" (UID STAGING_UID) '
                                  'already has a folder named "Production" (PRODUCTION_UID). After the rename, a '
                                  'lookup of this name fails because the name is not unique.')

    def test_double_quote_in_the_new_name_is_escaped(self):
        name = 'Prod "EU"'
        message = self._warning_for(_tree() + [_folder("QUOTED_UID", DATABASES, name)], STAGING, name)

        self.assertIn('already has a folder named "Prod \\"EU\\"" (QUOTED_UID).', message)

    def test_newline_in_the_new_name_is_escaped(self):
        """A newline or a carriage return inside the name is shown as an escape, not as a line break."""
        for name, shown in (("Prod\nEU", '"Prod\\nEU"'), ("Prod\rEU", '"Prod\\rEU"')):
            with self.subTest(name=name):
                message = self._warning_for(_tree() + [_folder("NEWLINE_UID", DATABASES, name)], STAGING, name)

                self.assertIn("already has a folder named {} (NEWLINE_UID).".format(shown), message)
                self.assertNotIn("\n", message, "a raw newline would split the warning over two lines")
                self.assertNotIn("\r", message)

    def test_tab_and_backslash_in_the_new_name_are_escaped(self):
        name = "A\tB\\C"
        message = self._warning_for(_tree() + [_folder("TAB_UID", DATABASES, name)], STAGING, name)

        self.assertIn('already has a folder named "A\\tB\\\\C" (TAB_UID).', message)

    def test_special_characters_in_the_folder_path_are_escaped(self):
        """The label quotes the whole path, so a quote or a newline in a parent's name is escaped too."""
        folders = [
            _folder(SHARED_INFRA, "", 'Infra "Main"'),
            _folder(DATABASES, SHARED_INFRA, "Data\nbases"),
            _folder(STAGING, DATABASES, "Staging"),
            _folder(PRODUCTION, DATABASES, "Production"),
        ]
        message = self._warning_for(folders, STAGING, "Production")

        self.assertIn('The parent of the folder "Infra \\"Main\\"/Data\\nbases/Staging" (UID STAGING_UID) already has '
                      'a folder named "Production" (PRODUCTION_UID).', message)

    def test_non_ascii_characters_are_not_escaped(self):
        name = "Caf\u00e9 \u6570\u636e \U0001F512"
        message = self._warning_for(_tree() + [_folder("CAFE_UID", DATABASES, name)], STAGING, name)

        self.assertIn('already has a folder named "Caf\u00e9 \u6570\u636e \U0001F512" (CAFE_UID).', message)
        self.assertNotIn("\\u", message)

    def test_sdk_error_label_escapes_a_double_quote(self):
        keeper = _keeper(_tree() + [_folder("QUOTED_UID", DATABASES, 'A "B"')])
        keeper.client.update_folder.side_effect = KeeperError("access_denied")

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder("QUOTED_UID", "C")

        self.assertEqual(str(context.exception),
                         'Cannot rename the folder "Infrastructure/Databases/A \\"B\\"" (UID QUOTED_UID): '
                         'access_denied')

    def test_sdk_error_label_escapes_a_newline(self):
        keeper = _keeper(_tree() + [_folder("NEWLINE_UID", DATABASES, "Prod\n")])
        keeper.client.update_folder.side_effect = KeeperError("access_denied")

        with self.assertRaises(KeeperFolderError) as context:
            keeper.update_folder("NEWLINE_UID", "Prod")

        self.assertEqual(str(context.exception),
                         'Cannot rename the folder "Infrastructure/Databases/Prod\\n" (UID NEWLINE_UID): access_denied')

    def test_no_op_debug_message_quotes_the_name(self):
        keeper = _keeper(_tree() + [_folder("NEWLINE_UID", DATABASES, "Prod\nEU")])

        with patch("keeper_secrets_manager_ansible.display.vvv") as vvv:
            result = keeper.update_folder("NEWLINE_UID", "Prod\nEU")

        self.assertIs(result["changed"], False)
        vvv.assert_called_once_with('Folder NEWLINE_UID is already named "Prod\\nEU". Nothing to rename.')


class KeeperUpdateFolderArgumentSpecTest(unittest.TestCase):
    """
    The task options, checked by validate_task_args with the plugin's ARGUMENT_SPEC before any connection. A bad option
    raises KeeperArgumentError (a ValueError, not an AnsibleError). A null value, or a value of the wrong type, of an
    option of this module is found first, and then the validator does not run. Every message is joined with "; ".
    """

    def _validate(self, task_args, ignore=None):
        return KeeperAnsible.validate_task_args("keeper_update_folder", task_args, ActionModule.ARGUMENT_SPEC,
                                                ignore=ignore)

    def _validate_error(self, task_args, ignore=None):
        with self.assertRaises(KeeperArgumentError) as context:
            self._validate(task_args, ignore=ignore)
        self.assertIsInstance(context.exception, ValueError)
        self.assertNotIsInstance(context.exception, AnsibleError)
        return str(context.exception)

    def assert_unsupported(self, message, before):
        """The message is exactly `before`, then the list of this module's options, in any order."""
        self.assertEqual(_split_supported(message), (before, OPTIONS), message)

    def test_argument_spec_is_two_required_strings(self):
        """Both options are required strings with no aliases and no defaults, and there are no other options."""
        self.assertEqual(ActionModule.ARGUMENT_SPEC, {
            "folder_uid": {"type": "str", "required": True},
            "new_folder_name": {"type": "str", "required": True},
        })

    def test_valid_arguments(self):
        self.assertEqual(self._validate({"folder_uid": STAGING, "new_folder_name": "QA"}),
                         {"folder_uid": STAGING, "new_folder_name": "QA"})

    def test_values_are_not_stripped_or_changed(self):
        """The spec does not strip or change the values; the module method decides what a padded value means."""
        self.assertEqual(self._validate({"folder_uid": " ABC", "new_folder_name": "Name "}),
                         {"folder_uid": " ABC", "new_folder_name": "Name "})

    def test_task_args_are_not_changed(self):
        """validate_task_args works on a copy: the task's own args stay as they were, also the removed ones."""
        task_args = {"folder_uid": STAGING, "new_folder_name": "QA", "cache": "C"}

        self._validate(task_args, ignore={"cache"})

        self.assertEqual(task_args, {"folder_uid": STAGING, "new_folder_name": "QA", "cache": "C"})

    def test_missing_folder_uid(self):
        self.assertEqual(self._validate_error({"new_folder_name": "QA"}), "missing required arguments: folder_uid")

    def test_missing_new_folder_name(self):
        self.assertEqual(self._validate_error({"folder_uid": STAGING}),
                         "missing required arguments: new_folder_name")

    def test_missing_both(self):
        self.assertEqual(self._validate_error({}), "missing required arguments: folder_uid, new_folder_name")

    def test_typo_new_name_fails(self):
        """new_name instead of new_folder_name must fail, not be ignored. Both errors are in one message."""
        message = self._validate_error({"folder_uid": STAGING, "new_name": "QA"})

        self.assert_unsupported(message, "missing required arguments: new_folder_name; Unsupported parameters for "
                                         "(keeper_update_folder) module: new_name. ")

    def test_extra_folder_name_option_fails(self):
        """folder_name (the option of the other folder modules) is not an option of this module."""
        message = self._validate_error({"folder_uid": STAGING, "new_folder_name": "QA", "folder_name": "Staging"})

        self.assert_unsupported(message, "Unsupported parameters for (keeper_update_folder) module: folder_name. ")

    def test_other_typos_fail(self):
        for option in ("name", "uid", "folder", "new_folder", "shared_folder_uid", "force", "Folder_uid", "cache"):
            with self.subTest(option=option):
                message = self._validate_error({"folder_uid": STAGING, "new_folder_name": "QA", option: "x"})

                self.assert_unsupported(
                    message, "Unsupported parameters for (keeper_update_folder) module: {}. ".format(option))

    def test_several_typos_are_listed_in_one_message(self):
        message = self._validate_error({"folder_uid": STAGING, "new_folder_name": "QA", "uid": 1, "name": 2})

        self.assert_unsupported(message, "Unsupported parameters for (keeper_update_folder) module: name, uid. ")

    def test_int_values_are_rejected(self):
        """
        An int is not accepted, as the UID or as the name. YAML changes the text of some numbers that have no quotes,
        so str() of the int is not always the text that the playbook author wrote.
        """
        cases = [
            ({"folder_uid": 123, "new_folder_name": "QA"}, WRONG_TYPE.format("folder_uid", "a number (123)")),
            ({"folder_uid": STAGING, "new_folder_name": 2024}, WRONG_TYPE.format("new_folder_name", "a number (2024)")),
            ({"folder_uid": STAGING, "new_folder_name": 0}, WRONG_TYPE.format("new_folder_name", "a number (0)")),
        ]
        for task_args, message in cases:
            with self.subTest(task_args=task_args):
                self.assertEqual(self._validate_error(task_args), message)

    def test_unquoted_yaml_numbers_are_rejected_with_the_value_that_yaml_made(self):
        """
        The numbers that YAML changes when they have no quotes: 007 becomes 7, 010 (octal) becomes 8, 0x1F (hex)
        becomes 31, 1_000 becomes 1000, and 1.10 becomes 1.1. The message shows the changed value, so the author can
        see why the name is not the one in the playbook.
        """
        from ansible.parsing.yaml.loader import AnsibleLoader

        for text, shown in (("007", "7"), ("010", "8"), ("0x1F", "31"), ("1_000", "1000"), ("1.10", "1.1"),
                            ("2024", "2024")):
            with self.subTest(text=text):
                value = AnsibleLoader("new_folder_name: " + text).get_single_data()["new_folder_name"]

                message = self._validate_error({"folder_uid": STAGING, "new_folder_name": value})

                self.assertEqual(message, WRONG_TYPE.format("new_folder_name", "a number ({})".format(shown)))

    def test_quoted_numbers_are_accepted_as_written(self):
        """With quotes, YAML keeps the text: "007" stays "007", and "2024" stays "2024"."""
        from ansible.parsing.yaml.loader import AnsibleLoader

        loaded = AnsibleLoader('folder_uid: "123"\nnew_folder_name: "007"\n').get_single_data()

        self.assertEqual(self._validate(dict(loaded)), {"folder_uid": "123", "new_folder_name": "007"})
        self.assertEqual(self._validate({"folder_uid": STAGING, "new_folder_name": "2024"}),
                         {"folder_uid": STAGING, "new_folder_name": "2024"})

    def test_vault_encrypted_values_are_accepted_and_decrypted(self):
        """
        A value that the playbook encrypts with !vault is a string, but before ansible-core 2.19 it is not a str. It
        is accepted, and the validated value is the decrypted str, not the vault object.
        """
        (folder_uid, new_name), context = _vaulted("FOLDER_UID", "Production")
        self.assertNotIsInstance(folder_uid, str)

        with context:
            validated = self._validate({"folder_uid": folder_uid, "new_folder_name": new_name})

        self.assertEqual(validated, {"folder_uid": "FOLDER_UID", "new_folder_name": "Production"})
        for value in validated.values():
            self.assertIsInstance(value, str)

    def test_null_folder_uid_fails(self):
        self.assertEqual(self._validate_error({"folder_uid": None, "new_folder_name": "QA"}),
                         NULL_OPTION.format("folder_uid"))

    def test_null_new_folder_name_fails(self):
        """
        A null name usually comes from a template variable with no value. It is an error here, at the option check,
        not a blank name later, so the task fails before it connects.
        """
        self.assertEqual(self._validate_error({"folder_uid": STAGING, "new_folder_name": None}),
                         NULL_OPTION.format("new_folder_name"))

    def test_both_null_are_reported_in_sorted_order(self):
        """
        The options are checked in sorted order, whatever the order of the task args. A message that ends with a
        period is followed by a space, not by "; ".
        """
        message = self._validate_error({"new_folder_name": None, "folder_uid": None})

        self.assertEqual(message, NULL_OPTION.format("folder_uid") + " " + NULL_OPTION.format("new_folder_name"))

    def test_null_hides_the_other_errors(self):
        """If a pre-check fails, the validator does not run: no "missing" or "Unsupported" part in the message."""
        message = self._validate_error({"new_name": "QA", "folder_uid": None})

        self.assertEqual(message, NULL_OPTION.format("folder_uid"))

    def test_null_value_of_an_unknown_option_is_an_unsupported_parameter(self):
        """The null check is only for the options of this module. An unknown option is reported as unsupported."""
        message = self._validate_error({"folder_uid": STAGING, "new_folder_name": "QA", "new_name": None})

        self.assert_unsupported(message, "Unsupported parameters for (keeper_update_folder) module: new_name. ")

    def test_non_string_new_folder_name_fails(self):
        """A list, a dictionary, a boolean, a number, a date, or another type is not turned into a folder name."""
        for value, kind in WRONG_TYPES:
            with self.subTest(value=value):
                message = self._validate_error({"folder_uid": STAGING, "new_folder_name": value})

                self.assertEqual(message, WRONG_TYPE.format("new_folder_name", kind))

    def test_non_string_folder_uid_fails(self):
        for value, kind in WRONG_TYPES:
            with self.subTest(value=value):
                message = self._validate_error({"folder_uid": value, "new_folder_name": "QA"})

                self.assertEqual(message, WRONG_TYPE.format("folder_uid", kind))

    def test_null_and_type_errors_are_reported_together_in_sorted_order(self):
        message = self._validate_error({"new_folder_name": True, "folder_uid": None})

        self.assertEqual(message, NULL_OPTION.format("folder_uid") + " " +
                         WRONG_TYPE.format("new_folder_name", "a boolean (True)"))

    def test_type_error_hides_the_other_errors(self):
        message = self._validate_error({"folder_uid": [STAGING], "typo": 1})

        self.assertEqual(message, WRONG_TYPE.format("folder_uid", "a list"))

    def test_group_default_options_of_other_modules_are_removed(self):
        """
        Ansible gives the defaults of an action group to every module in the group. The options that only other
        folder or record modules have are removed for this module when they are in the ignore list.
        """
        others = {"shared_folder_uid": "S", "subfolder_uid": "SUB", "folder_name": "F", "folder_path": "P",
                  "include_subfolders": True, "force": True, "cache": "C", "uid": "R"}

        validated = self._validate(dict(others, folder_uid=STAGING, new_folder_name="QA"), ignore=set(others))

        self.assertEqual(validated, {"folder_uid": STAGING, "new_folder_name": "QA"})

    def test_removed_group_default_can_be_null_or_of_any_type(self):
        """A group default for another module is removed before the checks, so its value does not matter here."""
        task_args = {"folder_uid": STAGING, "new_folder_name": "QA", "cache": None, "force": True,
                     "folder_path": ["A", "B"]}

        validated = self._validate(task_args, ignore={"cache", "force", "folder_path"})

        self.assertEqual(validated, {"folder_uid": STAGING, "new_folder_name": "QA"})

    def test_ignore_list_does_not_hide_a_misspelled_option(self):
        message = self._validate_error({"folder_uid": STAGING, "new_name": "QA", "shared_folder_uid": "S"},
                                       ignore={"shared_folder_uid", "cache"})

        self.assert_unsupported(message, "missing required arguments: new_folder_name; Unsupported parameters for "
                                         "(keeper_update_folder) module: new_name. ")

    def test_own_options_are_never_removed(self):
        validated = self._validate({"folder_uid": STAGING, "new_folder_name": "QA"},
                                   ignore={"folder_uid", "new_folder_name"})

        self.assertEqual(validated, {"folder_uid": STAGING, "new_folder_name": "QA"})

    def test_own_options_are_still_checked_when_they_are_in_the_ignore_list(self):
        cases = [
            ({"folder_uid": STAGING}, "missing required arguments: new_folder_name"),
            ({"folder_uid": STAGING, "new_folder_name": None}, NULL_OPTION.format("new_folder_name")),
            ({"folder_uid": STAGING, "new_folder_name": ["QA"]}, WRONG_TYPE.format("new_folder_name", "a list")),
        ]
        for task_args, expected in cases:
            with self.subTest(task_args=task_args):
                message = self._validate_error(task_args, ignore={"folder_uid", "new_folder_name"})

                self.assertEqual(message, expected)

    def test_task_option_with_the_name_of_a_group_default_is_removed(self):
        """
        The known limit of the ignore list: a task option with the same name as a group default (here a
        shared_folder_uid written in the task by mistake) cannot be told apart from the default. It is removed,
        not reported.
        """
        validated = self._validate({"folder_uid": STAGING, "new_folder_name": "QA", "shared_folder_uid": "X"},
                                   ignore={"shared_folder_uid"})

        self.assertEqual(validated, {"folder_uid": STAGING, "new_folder_name": "QA"})


class KeeperUpdateFolderDocumentationTest(unittest.TestCase):
    """
    ansible-doc reads the docs-only stub in plugins/modules, and the action plugin carries a copy. The two copies must
    be the same, and they must describe the options and the result that the code really has.
    """

    def _description(self):
        items = yaml.safe_load(action_plugin.DOCUMENTATION)["description"]
        return " ".join(" ".join(items).split())

    def test_docs_stub_is_identical_to_the_action_plugin(self):
        for name in ("DOCUMENTATION", "EXAMPLES", "RETURN"):
            with self.subTest(name=name):
                self.assertEqual(getattr(docs_stub, name), getattr(action_plugin, name))

    def test_documented_options_match_the_argument_spec(self):
        options = yaml.safe_load(action_plugin.DOCUMENTATION)["options"]

        self.assertEqual(sorted(options), sorted(ActionModule.ARGUMENT_SPEC))
        for name, spec in ActionModule.ARGUMENT_SPEC.items():
            with self.subTest(option=name):
                self.assertEqual(options[name]["type"], spec["type"])
                self.assertIs(options[name].get("required", False), spec.get("required", False))

    def test_description_says_how_the_names_are_compared(self):
        text = self._description()

        self.assertIn("The names are compared exactly, and the comparison is case-sensitive.", text)
        self.assertIn("A new name with a space, a tab, or a newline at the start or the end fails the task, because "
                      "a later lookup of the name would not find the folder.", text)
        self.assertNotIn("with any spaces", text, "the docs must not say that a padded new name is used as given")

    def test_description_says_that_the_options_are_checked(self):
        self.assertIn("The module checks its options. An unknown or misspelled option, an option set to null, or a "
                      "value of the wrong type fails the task. There is one exception. An option that a "
                      "module_defaults entry for an action group of this collection sets, and that this module does "
                      "not have, is ignored.", self._description())

    def test_return_folder_name_mentions_check_mode(self):
        returned = yaml.safe_load(action_plugin.RETURN)

        self.assertEqual(returned["folder_name"]["description"], "The name of the folder after the task. In check "
                                                                 "mode, the name that a real run gives the folder.")

    def test_documented_return_values_match_the_result(self):
        """RETURN lists every key of the result except changed, which every module returns."""
        documented = sorted(yaml.safe_load(action_plugin.RETURN))
        result = _keeper(_tree()).update_folder(STAGING, "QA")

        self.assertEqual(documented, sorted(k for k in result if k != "changed"))

    def test_examples_use_only_documented_options_and_return_values(self):
        options = set(yaml.safe_load(action_plugin.DOCUMENTATION)["options"])
        returned = set(yaml.safe_load(action_plugin.RETURN))
        examples = yaml.safe_load(action_plugin.EXAMPLES)

        renames = [task for task in examples if "keeper_update_folder" in task]
        self.assertGreater(len(renames), 0)
        for task in renames:
            self.assertEqual(set(task["keeper_update_folder"]), options, "every required option must be shown")
        registered = renames[0]["register"]
        shown = " ".join(str(task.get("debug", "")) for task in examples)
        for key in ("folder_name", "previous_folder_name"):
            self.assertIn("{}.{}".format(registered, key), shown)
            self.assertIn(key, returned)


class _FakeTemplar:
    """Resolves template strings from a dictionary, and records what it was asked to resolve."""

    def __init__(self, values):
        self.values = values
        self.calls = []

    def template(self, value):
        self.calls.append(value)
        return self.values[value]


class KeeperUpdateFolderActionPluginTest(unittest.TestCase):
    """
    The action plugin: it checks the options before it creates KeeperAnsible (so before any connection), with the
    option names of the group defaults as the ignore list. It passes check mode as a bool, and returns the method's
    result. It returns every failure as {"failed": True, "changed": False, "msg": ...}, and does not raise, so that
    failed_when, ignore_errors, and rescue work on it. Only a config error from the KeeperAnsible constructor raises.
    """

    def _run(self, task_args, check_mode=False, folders=None, update_error=None, method_error=None,
             module_defaults=None, templar=None, init_error=None):
        client = create_autospec(SecretsManager, instance=True)
        client.get_folders.return_value = _tree() if folders is None else folders
        if update_error is not None:
            client.update_folder.side_effect = update_error
        created = []

        def fake_init(keeper, task_vars, action_module=None, task_attributes=None, force_in_memory=False):
            created.append(action_module)
            if init_error is not None:
                raise init_error
            keeper.client = client

        action = object.__new__(ActionModule)
        action._task = SimpleNamespace(args=task_args, check_mode=check_mode,
                                       module_defaults=[] if module_defaults is None else module_defaults)
        action._templar = templar

        # ActionModule.__bases__[0] is the ActionBase that the plugin module imported. The test framework unloads
        # and reloads the ansible modules between playbook runs, so a fresh "from ansible.plugins.action import
        # ActionBase" can be a different class.
        with patch.object(ActionModule.__bases__[0], "run", return_value={}), \
                patch.object(KeeperAnsible, "__init__", fake_init), \
                patch.object(KeeperAnsible, "update_folder", autospec=True,
                             side_effect=method_error or KeeperAnsible.update_folder) as method:
            result = action.run(task_vars={})
        return SimpleNamespace(result=result, client=client, created=created, method=method, action=action)

    def assert_failure_before_connecting(self, run, message):
        self.assertEqual(run.result, {"failed": True, "changed": False, "msg": message})
        self.assertEqual(run.created, [], "KeeperAnsible must not be created when the options are wrong")
        self.assertEqual(run.client.mock_calls, [])
        run.method.assert_not_called()

    def assert_unsupported_failure(self, run, before):
        """A returned failure whose message is `before`, then this module's options in any order."""
        self.assertEqual(set(run.result), {"failed", "changed", "msg"})
        self.assertIs(run.result["failed"], True)
        self.assertIs(run.result["changed"], False)
        self.assertEqual(_split_supported(run.result["msg"]), (before, OPTIONS), run.result["msg"])
        self.assertEqual(run.created, [])
        self.assertEqual(run.client.mock_calls, [])

    def test_rename_through_the_plugin(self):
        run = self._run({"folder_uid": STAGING, "new_folder_name": "QA"})

        self.assertEqual(run.result, {"changed": True, "folder_uid": STAGING, "folder_name": "QA",
                                      "previous_folder_name": "Staging"})
        self.assertEqual(run.created, [run.action], "KeeperAnsible must be created once, with the action module")
        run.client.update_folder.assert_called_once_with(STAGING, "QA", folders=run.client.get_folders.return_value)

    def test_no_op_through_the_plugin(self):
        run = self._run({"folder_uid": STAGING, "new_folder_name": "Staging"})

        self.assertEqual(run.result, {"changed": False, "folder_uid": STAGING, "folder_name": "Staging",
                                      "previous_folder_name": "Staging"})
        run.client.update_folder.assert_not_called()

    def test_check_mode_is_passed_to_the_method(self):
        run = self._run({"folder_uid": STAGING, "new_folder_name": "QA"}, check_mode=True)

        self.assertIs(run.method.call_args.kwargs["check_mode"], True)
        self.assertEqual(run.result, {"changed": True, "folder_uid": STAGING, "folder_name": "QA",
                                      "previous_folder_name": "Staging"})
        run.client.update_folder.assert_not_called()

    def test_normal_run_passes_check_mode_false(self):
        for check_mode in (False, None):
            with self.subTest(check_mode=check_mode):
                run = self._run({"folder_uid": STAGING, "new_folder_name": "QA"}, check_mode=check_mode)

                self.assertIs(run.method.call_args.kwargs["check_mode"], False)
                run.client.update_folder.assert_called_once()

    def test_validated_values_reach_the_method(self):
        """
        The plugin passes the values from the option check, not the raw task args. A !vault value is decrypted there,
        so the method and the SDK get the decrypted str, not the vault object. A vault object compares equal to its
        text, so the test checks the type too.
        """
        (folder_uid, new_name), context = _vaulted(STAGING, "QA")

        with context:
            run = self._run({"folder_uid": folder_uid, "new_folder_name": new_name})

        passed_uid, passed_name = run.method.call_args[0][1:]
        self.assertIsInstance(passed_uid, str, "the method must get the decrypted UID, not the vault object")
        self.assertIsInstance(passed_name, str, "the method must get the decrypted name, not the vault object")
        self.assertEqual((str(passed_uid), str(passed_name)), (STAGING, "QA"))
        self.assertEqual(run.result, {"changed": True, "folder_uid": STAGING, "folder_name": "QA",
                                      "previous_folder_name": "Staging"})
        run.client.update_folder.assert_called_once_with(STAGING, "QA", folders=run.client.get_folders.return_value)

    def test_typo_option_returns_a_failure_before_connecting(self):
        run = self._run({"folder_uid": STAGING, "new_name": "QA"})

        self.assert_unsupported_failure(run, "missing required arguments: new_folder_name; Unsupported parameters "
                                             "for (keeper_update_folder) module: new_name. ")

    def test_missing_option_returns_a_failure_before_connecting(self):
        run = self._run({"new_folder_name": "QA"})

        self.assert_failure_before_connecting(run, "missing required arguments: folder_uid")

    def test_null_option_returns_a_failure_before_connecting(self):
        for task_args, option in (({"folder_uid": STAGING, "new_folder_name": None}, "new_folder_name"),
                                  ({"folder_uid": None, "new_folder_name": "QA"}, "folder_uid")):
            with self.subTest(option=option):
                run = self._run(task_args)

                self.assert_failure_before_connecting(run, NULL_OPTION.format(option))

    def test_wrong_type_returns_a_failure_before_connecting(self):
        for task_args, message in (
                ({"folder_uid": STAGING, "new_folder_name": ["Prod", "EU"]}, WRONG_TYPE.format("new_folder_name",
                                                                                               "a list")),
                ({"folder_uid": True, "new_folder_name": "QA"}, WRONG_TYPE.format("folder_uid", "a boolean (True)")),
                ({"folder_uid": STAGING, "new_folder_name": 1.1}, WRONG_TYPE.format("new_folder_name",
                                                                                   "a number (1.1)")),
                ({"folder_uid": STAGING, "new_folder_name": 2026}, WRONG_TYPE.format("new_folder_name",
                                                                                    "a number (2026)")),
        ):
            with self.subTest(task_args=task_args):
                self.assert_failure_before_connecting(self._run(task_args), message)

    def test_missing_folder_returns_the_wrapped_failure(self):
        run = self._run({"folder_uid": MISSING, "new_folder_name": "QA"})

        self.assertEqual(run.result, {"failed": True, "changed": False,
                                      "msg": "Could not update folder: " + NOT_FOUND.format(MISSING)})
        run.client.update_folder.assert_not_called()

    def test_padded_name_returns_the_wrapped_failure(self):
        """The padding check is in the method, so the plugin returns it with its prefix. No request is sent."""
        run = self._run({"folder_uid": STAGING, "new_folder_name": "Production\n"})

        self.assertEqual(run.result, {"failed": True, "changed": False,
                                      "msg": "Could not update folder: " + _padded_message("'Production\\n'")})
        self.assertEqual(run.client.mock_calls, [])

    def test_blank_name_returns_the_wrapped_failure(self):
        run = self._run({"folder_uid": STAGING, "new_folder_name": "   "})

        self.assertEqual(run.result,
                         {"failed": True, "changed": False, "msg": "Could not update folder: " + BLANK_NAME})
        self.assertEqual(run.client.mock_calls, [])

    def test_sdk_error_returns_the_wrapped_failure(self):
        run = self._run({"folder_uid": STAGING, "new_folder_name": "QA"}, update_error=KeeperError("access_denied"))

        self.assertEqual(run.result, {"failed": True, "changed": False, "msg": "Could not update folder: Cannot rename "
                                                                             "the folder {}: access_denied".format(
                                                                                 STAGING_LABEL)})

    def test_any_method_exception_returns_the_wrapped_failure(self):
        """Not only a KeeperFolderError: any exception from the method becomes the returned failure."""
        run = self._run({"folder_uid": STAGING, "new_folder_name": "QA"}, method_error=RuntimeError("unexpected"))

        self.assertEqual(run.result, {"failed": True, "changed": False, "msg": "Could not update folder: unexpected"})

    def test_config_error_from_the_constructor_still_raises(self):
        """The KeeperAnsible constructor is outside the try, so a config error is raised, not returned."""
        with self.assertRaises(AnsibleError) as context:
            self._run({"folder_uid": STAGING, "new_folder_name": "QA"},
                      init_error=AnsibleError("Keeper Ansible error: no config"))

        self.assertEqual(context.exception.args[0], "Keeper Ansible error: no config")

    def test_group_defaults_for_other_modules_are_ignored(self):
        """
        Ansible merges the group defaults into the task args. The options that this module does not have
        (shared_folder_uid and cache here) are ignored, and the rename works.
        """
        run = self._run({"folder_uid": STAGING, "new_folder_name": "QA", "shared_folder_uid": "S", "cache": "C"},
                        module_defaults=[{GROUP: {"shared_folder_uid": "S", "cache": "C"}}])

        self.assertEqual(run.result, {"changed": True, "folder_uid": STAGING, "folder_name": "QA",
                                      "previous_folder_name": "Staging"})
        self.assertEqual(run.method.call_args[0][1:], (STAGING, "QA"))

    def test_group_defaults_do_not_hide_a_misspelled_task_option(self):
        run = self._run({"folder_uid": STAGING, "new_name": "QA", "shared_folder_uid": "S", "cache": "C"},
                        module_defaults=[{GROUP: {"shared_folder_uid": "S", "cache": "C"}}])

        self.assert_unsupported_failure(run, "missing required arguments: new_folder_name; Unsupported parameters "
                                             "for (keeper_update_folder) module: new_name. ")

    def test_group_default_for_an_own_option_does_not_remove_the_task_value(self):
        """
        A group default for folder_uid (an option of this module) must not remove the folder_uid that the task gives.
        Ansible lets a task value override a default, so the task's UID is renamed.
        """
        run = self._run({"folder_uid": STAGING, "new_folder_name": "QA"},
                        module_defaults=[{GROUP: {"folder_uid": "DEFAULT_UID"}}])

        self.assertEqual(run.result["folder_uid"], STAGING)
        run.client.update_folder.assert_called_once_with(STAGING, "QA", folders=run.client.get_folders.return_value)

    def test_templated_group_defaults_are_resolved_with_the_plugin_templar(self):
        """A group default given as one template string is resolved with the action plugin's own templar."""
        templar = _FakeTemplar({"{{ keeper_defaults }}": {"shared_folder_uid": "S", "cache": "C"}})

        run = self._run({"folder_uid": STAGING, "new_folder_name": "QA", "shared_folder_uid": "S", "cache": "C"},
                        module_defaults=[{GROUP: "{{ keeper_defaults }}"}], templar=templar)

        self.assertEqual(templar.calls, ["{{ keeper_defaults }}"])
        self.assertIs(run.result["changed"], True)
        self.assertEqual(run.method.call_args[0][1:], (STAGING, "QA"))

    def test_group_defaults_of_another_collection_do_not_hide_a_misspelled_option(self):
        """
        Ansible gives a group default only to the modules in that group, so the defaults of another collection's group
        never reach this module. Their option names must not hide a mistake: a region written in this task fails.
        """
        run = self._run({"folder_uid": STAGING, "new_folder_name": "QA", "region": "us-east-1"},
                        module_defaults=[{"group/amazon.aws.aws": {"region": "us-east-1"}}])

        self.assert_unsupported_failure(run, "Unsupported parameters for (keeper_update_folder) module: region. ")

    def test_defaults_of_one_other_module_are_not_ignored(self):
        """
        Defaults for one named module are not group defaults. Ansible does not give them to this module, so the
        same option in this task was written in the task, and it must fail.
        """
        run = self._run({"folder_uid": STAGING, "new_folder_name": "QA", "shared_folder_uid": "S"},
                        module_defaults=[{"keepersecurity.keeper_secrets_manager.keeper_create_folder":
                                          {"shared_folder_uid": "S"}}])

        self.assert_unsupported_failure(run, "Unsupported parameters for (keeper_update_folder) module: "
                                             "shared_folder_uid. ")


if __name__ == "__main__":
    unittest.main()
