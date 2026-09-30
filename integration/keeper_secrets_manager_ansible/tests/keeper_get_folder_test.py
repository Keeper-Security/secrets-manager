"""
Unit tests for KeeperAnsible.get_folder() and the keeper_get_folder action plugin.

The client is a MagicMock that returns real KeeperFolder objects, so each test controls the folder tree exactly and
can see every SDK call. keeper_get_folder_playbook_test.py runs the same module through ansible-playbook and the
real SDK.
"""
import datetime
import decimal
import importlib
import signal
import sys
import threading
import unicodedata
import unittest
from unittest.mock import MagicMock, patch

import yaml
from keeper_secrets_manager_core.dto.dtos import KeeperFolder
from keeper_secrets_manager_core.exceptions import KeeperError

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperArgumentError, KeeperFolderError
from keeper_secrets_manager_ansible.plugins.modules import keeper_get_folder as module_docs

ACTION_PLUGIN = "keeper_secrets_manager_ansible.plugins.action.keeper_get_folder"


def action_plugin():
    """
    Import the action plugin when a test needs it, not when pytest collects this file. The import loads
    ansible.plugins.loader. A loader that is loaded before AnsibleTestFramework sets the plugin paths cannot find
    the Keeper plugins, so every playbook test after it would fail with a parser error.
    """
    return importlib.import_module(ACTION_PLUGIN)


def tearDownModule():
    """
    Unload the ansible modules, as AnsibleTestFramework does after each playbook run. So a playbook test that
    runs after this file loads a new plugin loader, with the Keeper plugin paths.
    """
    for name in list(sys.modules):
        if name.startswith("ansible") or name == ACTION_PLUGIN:
            sys.modules.pop(name, None)


TOP_LEVEL = "at the top level (the shared folders of this KSM application)"
SUPPORTED_OPTION_NAMES = {"folder_name", "folder_path", "include_subfolders", "shared_folder_uid", "subfolder_uid"}
UNSUPPORTED_PREFIX = "Unsupported parameters for (keeper_get_folder) module: "
SUPPORTED_SEPARATOR = ". Supported parameters include: "

# A lookup in a few folders takes microseconds. A call that takes this long is in an endless loop.
HANG_SECONDS = 2.0


def folder(uid, parent_uid, name):
    return KeeperFolder(b"k" * 32, uid, parent_uid, name)


def standard_folders():
    """
    Infrastructure            SF_INFRA (shared folder)
        Databases             DB
            Production        PROD
                EU            EU
                    Frankfurt FRA
            Staging           STG
        Web                   WEB
            Databases         WEB_DB (the same name as DB, one level deeper)
        Prod/EU               SLASH (a name that contains "/")
        2024                  YEAR (a name that looks like a number)
    Applications              SF_APPS (shared folder)
        Dup                   DUP_1
        Dup                   DUP_2
            Leaf              LEAF (only the second "Dup" has it)
        Dup                   DUP_3
        Services              SVC
    Team                      SF_TEAM_1 (shared folder)
    Team                      SF_TEAM_2 (shared folder with the same name)
    """
    return [
        folder("SF_INFRA", "", "Infrastructure"),
        folder("SF_APPS", "", "Applications"),
        folder("SF_TEAM_1", "", "Team"),
        folder("SF_TEAM_2", "", "Team"),
        folder("DB", "SF_INFRA", "Databases"),
        folder("PROD", "DB", "Production"),
        folder("EU", "PROD", "EU"),
        folder("FRA", "EU", "Frankfurt"),
        folder("STG", "DB", "Staging"),
        folder("WEB", "SF_INFRA", "Web"),
        folder("WEB_DB", "WEB", "Databases"),
        folder("SLASH", "SF_INFRA", "Prod/EU"),
        folder("YEAR", "SF_INFRA", "2024"),
        folder("DUP_1", "SF_APPS", "Dup"),
        folder("DUP_2", "SF_APPS", "Dup"),
        folder("LEAF", "DUP_2", "Leaf"),
        folder("DUP_3", "SF_APPS", "Dup"),
        folder("SVC", "SF_APPS", "Services"),
    ]


def item(uid, name, parent_uid):
    """One entry of the subfolders list."""
    return {"folder_uid": uid, "folder_name": name, "parent_uid": parent_uid}


def not_found_in(name, path, uid):
    return 'No folder named "{}" was found in the folder "{}" (UID {}).'.format(name, path, uid)


def not_found_at_top(name):
    return 'No folder named "{}" was found {}.'.format(name, TOP_LEVEL)


def duplicates_in(name, path, uid, uids):
    return ('Found {n} folders named "{name}" in the folder "{path}" (UID {uid}): {uids}. Rename one of them in the '
            'vault. Or set subfolder_uid to the UID of the folder that you want, and remove "{name}" from folder_name '
            'or folder_path.').format(n=len(uids), name=name, path=path, uid=uid, uids=", ".join(uids))


def duplicates_at_top(name, uids):
    return ('Found {n} folders named "{name}" {top}: {uids}. Rename one of them in the vault. Or set shared_folder_uid '
            'to the UID of the folder that you want, and remove "{name}" from folder_name or folder_path.').format(
                n=len(uids), name=name, top=TOP_LEVEL, uids=", ".join(uids))


def null_message(option):
    return "The {} option is null. Give it a value, or leave the option out of the task.".format(option)


def type_message(option, kind):
    return ("The {} option must be a string, but it is {}. Put quotes around the value, or use the string "
            "filter.").format(option, kind)


def path_item_message(kind):
    return ("Each folder_path item must be a folder name, but one item is {}. Put quotes around the folder "
            "names.").format(kind)


def unsupported_names(message):
    """
    The unknown names and the supported names of an "Unsupported parameters" message, as two sets, or None if the
    message has another form. ansible-core 2.12 lists the names in set order and 2.21 sorts them, so a test must
    compare them as sets.
    """
    if not message.startswith(UNSUPPORTED_PREFIX) or not message.endswith(".") or SUPPORTED_SEPARATOR not in message:
        return None
    unknown, supported = message[len(UNSUPPORTED_PREFIX):-1].split(SUPPORTED_SEPARATOR)
    return set(unknown.split(", ")), set(supported.split(", "))


def empty_name(names_json):
    return ('The folder_path {} has an empty folder name. Look for a leading, trailing, or double "/", or an empty '
            'list item.').format(names_json)


WRONG_PATH_TYPE = "The folder_path must be a string or a list of folder names."
NOTHING_TO_LOOK_UP = "There is nothing to look up. Set shared_folder_uid, subfolder_uid, folder_name, or folder_path."


class LookupHung(BaseException):
    """
    Raised when a call runs too long. It is a BaseException, so an "except Exception" in the code under test cannot
    turn a hang into a different error.
    """


def call_with_time_limit(func, seconds=HANG_SECONDS):
    """
    Call func() and return its result, or raise LookupHung after the limit. Without a limit, a missing loop guard
    would stop the whole test run instead of failing one test.
    """
    if hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread():
        def on_alarm(signum, frame):
            raise LookupHung("the call did not return in {} seconds".format(seconds))

        previous = signal.signal(signal.SIGALRM, on_alarm)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            return func()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    # No SIGALRM (for example on Windows): run the call in a daemon thread, and stop waiting after the limit.
    outcome = {}

    def target():
        try:
            outcome["value"] = func()
        except BaseException as err:
            outcome["error"] = err

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise LookupHung("the call did not return in {} seconds".format(seconds))
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def validate(args):
    return KeeperAnsible.validate_task_args("keeper_get_folder", args, action_plugin().ActionModule.ARGUMENT_SPEC,
                                            mutually_exclusive=[["folder_name", "folder_path"]])


def argument_error(test, args):
    """The message of the KeeperArgumentError that validate() raises for args."""
    with test.assertRaises(KeeperArgumentError) as ctx:
        validate(args)
    test.assertIsInstance(ctx.exception, ValueError)
    return str(ctx.exception)


class GetFolderTestCase(unittest.TestCase):

    def make_keeper(self, folders=None):
        keeper = object.__new__(KeeperAnsible)
        keeper.client = MagicMock()
        keeper.client.get_folders.return_value = standard_folders() if folders is None else folders
        return keeper

    def call(self, keeper, **kwargs):
        try:
            return call_with_time_limit(lambda: keeper.get_folder(**kwargs))
        except LookupHung as err:
            self.fail("get_folder({}) did not return: {}".format(kwargs, err))

    def lookup(self, folders=None, **kwargs):
        return self.call(self.make_keeper(folders), **kwargs)

    def lookup_error(self, folders=None, **kwargs):
        return self.call_error(self.make_keeper(folders), **kwargs)

    def call_error(self, keeper, **kwargs):
        try:
            result = self.call(keeper, **kwargs)
        except KeeperFolderError as err:
            return str(err)
        self.fail("get_folder({}) returned {!r} instead of raising KeeperFolderError".format(kwargs, result))

    def uid_of(self, folders=None, **kwargs):
        return self.lookup(folders, **kwargs)["folder_uid"]


class KeeperGetFolderAcceptanceTest(GetFolderTestCase):
    """The acceptance criteria and the two in-scope nice-to-haves, one test each."""

    def test_shared_folder_uid_and_subfolder_name_return_the_subfolder_uid(self):
        """The main use: a playbook knows the shared folder UID and the subfolder name, and needs the UID."""
        result = self.lookup(shared_folder_uid="SF_INFRA", folder_name="Databases")
        self.assertEqual(result["folder_uid"], "DB")
        self.assertEqual(result, {
            "folder_uid": "DB",
            "folder_name": "Databases",
            "parent_uid": "SF_INFRA",
            "shared_folder_uid": "SF_INFRA",
        })

    def test_shared_folder_uid_only_returns_the_shared_folder_uid_and_name(self):
        """With no subfolder name, the result is the shared folder itself, not an error and not a child."""
        result = self.lookup(shared_folder_uid="SF_INFRA")
        self.assertEqual(result, {
            "folder_uid": "SF_INFRA",
            "folder_name": "Infrastructure",
            "parent_uid": "",
            "shared_folder_uid": "SF_INFRA",
        })

    def test_name_that_matches_no_folder_under_the_parent_fails_with_a_clear_error(self):
        """
        "Services" exists, but in another shared folder. A lookup under Infrastructure must fail and name the
        folder it looked in, instead of returning an empty value or the folder from the other shared folder.
        """
        keeper = self.make_keeper()
        message = self.call_error(keeper, shared_folder_uid="SF_INFRA", folder_name="Services")
        self.assertEqual(message, not_found_in("Services", "Infrastructure", "SF_INFRA"))

    def test_name_that_matches_no_folder_under_a_subfolder_parent_fails(self):
        """The same rule when the parent is a subfolder: "EU" exists, but two levels below Databases."""
        message = self.lookup_error(subfolder_uid="DB", folder_name="EU")
        self.assertEqual(message, not_found_in("EU", "Infrastructure/Databases", "DB"))

    def test_full_folder_path_resolves_in_one_call(self):
        """A full path from the top level gives the deep folder in one task."""
        result = self.lookup(folder_path="Infrastructure/Databases/Production/EU/Frankfurt")
        self.assertEqual(result, {
            "folder_uid": "FRA",
            "folder_name": "Frankfurt",
            "parent_uid": "EU",
            "shared_folder_uid": "SF_INFRA",
        })

    def test_full_folder_list_under_a_folder_is_returned_on_request(self):
        """include_subfolders returns every folder below the found folder."""
        result = self.lookup(shared_folder_uid="SF_INFRA", folder_name="Databases", include_subfolders=True)
        self.assertEqual(result["folder_uid"], "DB")
        self.assertEqual(result["subfolders"], [
            item("PROD", "Production", "DB"),
            item("EU", "EU", "PROD"),
            item("FRA", "Frankfurt", "EU"),
            item("STG", "Staging", "DB"),
        ])


class KeeperGetFolderStartFolderTest(GetFolderTestCase):
    """Which folder the lookup starts at, and the errors for a wrong start folder."""

    def test_shared_folder_uid_only_starts_at_the_shared_folder(self):
        self.assertEqual(self.uid_of(shared_folder_uid="SF_APPS", folder_name="Services"), "SVC")

    def test_subfolder_uid_only_returns_the_subfolder(self):
        """A subfolder UID alone is allowed, and with no name the result is that subfolder."""
        self.assertEqual(self.lookup(subfolder_uid="PROD"), {
            "folder_uid": "PROD",
            "folder_name": "Production",
            "parent_uid": "DB",
            "shared_folder_uid": "SF_INFRA",
        })

    def test_subfolder_uid_only_searches_inside_the_subfolder(self):
        self.assertEqual(self.uid_of(subfolder_uid="DB", folder_name="Production"), "PROD")
        self.assertEqual(self.uid_of(subfolder_uid="PROD", folder_path="EU/Frankfurt"), "FRA")

    def test_subfolder_uid_wins_over_shared_folder_uid_as_the_start(self):
        """With both UIDs, the name is looked up in the subfolder, not in the shared folder."""
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", subfolder_uid="EU", folder_name="Frankfurt"), "FRA")
        message = self.lookup_error(shared_folder_uid="SF_INFRA", subfolder_uid="PROD", folder_name="Databases")
        self.assertEqual(message, not_found_in("Databases", "Infrastructure/Databases/Production", "PROD"))

    def test_both_uids_with_a_deep_subfolder_and_no_name_return_the_subfolder(self):
        """The subfolder can be at any depth inside the shared folder."""
        self.assertEqual(self.lookup(shared_folder_uid="SF_INFRA", subfolder_uid="FRA"), {
            "folder_uid": "FRA",
            "folder_name": "Frankfurt",
            "parent_uid": "EU",
            "shared_folder_uid": "SF_INFRA",
        })

    def test_both_uids_fail_when_the_subfolder_is_not_inside_the_shared_folder(self):
        """A subfolder of another shared folder must fail, instead of silently searching outside the shared folder."""
        message = self.lookup_error(shared_folder_uid="SF_APPS", subfolder_uid="PROD", folder_name="EU")
        self.assertEqual(
            message,
            'The subfolder "Infrastructure/Databases/Production" (UID PROD) is not inside the shared folder '
            '"Applications" (UID SF_APPS).')

    def test_both_uids_fail_when_the_subfolder_uid_is_another_shared_folder(self):
        message = self.lookup_error(shared_folder_uid="SF_INFRA", subfolder_uid="SF_APPS")
        self.assertEqual(
            message,
            'The subfolder "Applications" (UID SF_APPS) is not inside the shared folder "Infrastructure" '
            '(UID SF_INFRA).')

    def test_equal_uids_start_at_the_shared_folder(self):
        """subfolder_uid equal to shared_folder_uid is allowed: the start is the shared folder."""
        self.assertEqual(self.lookup(shared_folder_uid="SF_INFRA", subfolder_uid="SF_INFRA"), {
            "folder_uid": "SF_INFRA",
            "folder_name": "Infrastructure",
            "parent_uid": "",
            "shared_folder_uid": "SF_INFRA",
        })
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", subfolder_uid="SF_INFRA", folder_name="Web"), "WEB")

    def test_no_uid_looks_up_folder_name_among_the_shared_folders(self):
        self.assertEqual(self.lookup(folder_name="Applications"), {
            "folder_uid": "SF_APPS",
            "folder_name": "Applications",
            "parent_uid": "",
            "shared_folder_uid": "SF_APPS",
        })

    def test_no_uid_walks_folder_path_from_the_shared_folders(self):
        self.assertEqual(self.uid_of(folder_path="Applications/Services"), "SVC")
        self.assertEqual(self.uid_of(folder_path=["Infrastructure", "Web", "Databases"]), "WEB_DB")

    def test_no_uid_does_not_find_a_subfolder_at_the_top_level(self):
        """At the top level only shared folders match. "Databases" is a subfolder, so it is not found there."""
        self.assertEqual(self.lookup_error(folder_name="Databases"), not_found_at_top("Databases"))
        self.assertEqual(self.lookup_error(folder_path="Production/EU"), not_found_at_top("Production"))

    def test_shared_folder_uid_that_is_a_subfolder_fails(self):
        """A subfolder UID in shared_folder_uid is a common mistake. The error says which option to use."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="DB", folder_name="Production"),
            'The folder "Infrastructure/Databases" (UID DB) is a subfolder, not a shared folder. '
            'Set it as subfolder_uid instead.')

    def test_shared_folder_uid_that_is_a_deep_subfolder_fails_with_its_full_path(self):
        self.assertEqual(
            self.lookup_error(shared_folder_uid="FRA"),
            'The folder "Infrastructure/Databases/Production/EU/Frankfurt" (UID FRA) is a subfolder, not a shared '
            'folder. Set it as subfolder_uid instead.')

    def test_shared_folder_uid_that_is_a_subfolder_fails_even_with_a_valid_subfolder_uid(self):
        message = self.lookup_error(shared_folder_uid="DB", subfolder_uid="PROD")
        self.assertIn("is a subfolder, not a shared folder. Set it as subfolder_uid instead.", message)

    def test_shared_folder_uid_not_found(self):
        self.assertEqual(
            self.lookup_error(shared_folder_uid="NO_SUCH_UID", folder_name="Databases"),
            "The shared folder NO_SUCH_UID was not found, or it is not shared to this KSM application.")

    def test_subfolder_uid_not_found(self):
        self.assertEqual(
            self.lookup_error(subfolder_uid="NO_SUCH_UID"),
            "The subfolder NO_SUCH_UID was not found, or it is not shared to this KSM application.")

    def test_subfolder_uid_not_found_in_a_valid_shared_folder(self):
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", subfolder_uid="NO_SUCH_UID", folder_name="EU"),
            "The subfolder NO_SUCH_UID was not found, or it is not shared to this KSM application.")

    def test_shared_folder_with_a_none_parent_uid_is_still_a_shared_folder(self):
        """Only "" comes from the SDK, but a None parent_uid must also mean "no parent", in the result too."""
        folders = [folder("SF_NONE", None, "Legacy"), folder("SUB", "SF_NONE", "Child")]
        self.assertEqual(self.lookup(folders, shared_folder_uid="SF_NONE"), {
            "folder_uid": "SF_NONE",
            "folder_name": "Legacy",
            "parent_uid": "",
            "shared_folder_uid": "SF_NONE",
        })
        self.assertEqual(self.uid_of(folders, folder_name="Legacy"), "SF_NONE")
        self.assertEqual(self.lookup(folders, folder_path="Legacy/Child")["shared_folder_uid"], "SF_NONE")


class KeeperGetFolderNameTest(GetFolderTestCase):
    """folder_name: an exact, case-sensitive match among the direct children of the start folder."""

    CASE_FOLDERS = [
        folder("SF_CASE", "", "Case"),
        folder("UPPER", "SF_CASE", "Databases"),
        folder("LOWER", "SF_CASE", "databases"),
    ]

    def test_match_is_case_sensitive(self):
        """
        "Databases" and "databases" are two folders. Each name finds only its own folder. A case-insensitive match
        would find both, and fail as a duplicate, or pick the wrong one.
        """
        self.assertEqual(self.uid_of(self.CASE_FOLDERS, shared_folder_uid="SF_CASE", folder_name="Databases"), "UPPER")
        self.assertEqual(self.uid_of(self.CASE_FOLDERS, shared_folder_uid="SF_CASE", folder_name="databases"), "LOWER")
        self.assertEqual(
            self.lookup_error(self.CASE_FOLDERS, shared_folder_uid="SF_CASE", folder_name="DATABASES"),
            not_found_in("DATABASES", "Case", "SF_CASE"))

    def test_match_is_case_sensitive_at_the_top_level(self):
        self.assertEqual(self.uid_of(self.CASE_FOLDERS, folder_name="Case"), "SF_CASE")
        self.assertEqual(self.lookup_error(self.CASE_FOLDERS, folder_name="case"), not_found_at_top("case"))

    def test_only_direct_children_match(self):
        """Not a recursive search: a grandchild name is not found in the start folder."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_name="Production"),
            not_found_in("Production", "Infrastructure", "SF_INFRA"))
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_name="Frankfurt"),
            not_found_in("Frankfurt", "Infrastructure", "SF_INFRA"))

    def test_a_same_named_grandchild_does_not_count_as_a_duplicate(self):
        """Infrastructure/Web/Databases has the same name as Infrastructure/Databases, but it is not a child."""
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", folder_name="Databases"), "DB")
        self.assertEqual(self.uid_of(subfolder_uid="WEB", folder_name="Databases"), "WEB_DB")

    def test_a_folder_of_another_shared_folder_does_not_match(self):
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_APPS", folder_name="Infrastructure"),
            not_found_in("Infrastructure", "Applications", "SF_APPS"))

    def test_duplicate_names_fail_and_list_every_uid(self):
        """Keeper allows same-named siblings. The module must not pick one; it must list all of them."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_APPS", folder_name="Dup"),
            duplicates_in("Dup", "Applications", "SF_APPS", ["DUP_1", "DUP_2", "DUP_3"]))

    def test_duplicate_names_below_a_subfolder_name_subfolder_uid(self):
        folders = standard_folders() + [folder("TWIN_1", "PROD", "Twin"), folder("TWIN_2", "PROD", "Twin")]
        self.assertEqual(
            self.lookup_error(folders, subfolder_uid="PROD", folder_name="Twin"),
            duplicates_in("Twin", "Infrastructure/Databases/Production", "PROD", ["TWIN_1", "TWIN_2"]))

    def test_duplicate_shared_folder_names_at_the_top_level_name_shared_folder_uid(self):
        """At the top level the duplicates are shared folders, so the error tells the user to set shared_folder_uid."""
        self.assertEqual(self.lookup_error(folder_name="Team"), duplicates_at_top("Team", ["SF_TEAM_1", "SF_TEAM_2"]))

    def test_duplicate_names_never_pick_one_in_any_order(self):
        """The error does not depend on which duplicate comes first in the list."""
        for folders in (standard_folders(), list(reversed(standard_folders()))):
            with self.subTest(first=folders[0].folder_uid):
                message = self.lookup_error(folders, shared_folder_uid="SF_APPS", folder_name="Dup")
                self.assertTrue(message.startswith('Found 3 folders named "Dup" in the folder "Applications"'), message)
                for uid in ("DUP_1", "DUP_2", "DUP_3"):
                    self.assertIn(uid, message)

    def test_duplicate_message_says_to_set_the_uid_and_remove_the_name(self):
        """The full text, written out, so that a change of the hint is seen."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_APPS", folder_name="Dup"),
            'Found 3 folders named "Dup" in the folder "Applications" (UID SF_APPS): DUP_1, DUP_2, DUP_3. Rename one '
            'of them in the vault. Or set subfolder_uid to the UID of the folder that you want, and remove "Dup" '
            'from folder_name or folder_path.')
        self.assertEqual(
            self.lookup_error(folder_name="Team"),
            'Found 2 folders named "Team" at the top level (the shared folders of this KSM application): SF_TEAM_1, '
            'SF_TEAM_2. Rename one of them in the vault. Or set shared_folder_uid to the UID of the folder that you '
            'want, and remove "Team" from folder_name or folder_path.')

    def test_the_duplicate_hint_works_only_when_the_name_is_removed(self):
        """With the UID set and the name kept, the lookup looks for "Dup" inside the duplicate, and fails."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_APPS", subfolder_uid="DUP_2", folder_name="Dup"),
            not_found_in("Dup", "Applications/Dup", "DUP_2"))
        self.assertEqual(self.uid_of(shared_folder_uid="SF_APPS", subfolder_uid="DUP_2"), "DUP_2")
        self.assertEqual(self.uid_of(shared_folder_uid="SF_TEAM_2"), "SF_TEAM_2")

    def test_unicode_names_match_exactly(self):
        folders = [
            folder("SF_U", "", "Équipe"),
            folder("U_FR", "SF_U", "Données"),
            folder("U_ZH", "SF_U", "数据库"),
            folder("U_EMOJI", "SF_U", "🔐 Secrets"),
            folder("U_DEEP", "U_FR", "Clés privées"),
        ]
        self.assertEqual(self.uid_of(folders, folder_name="Équipe"), "SF_U")
        self.assertEqual(self.uid_of(folders, shared_folder_uid="SF_U", folder_name="Données"), "U_FR")
        self.assertEqual(self.uid_of(folders, shared_folder_uid="SF_U", folder_name="数据库"), "U_ZH")
        self.assertEqual(self.uid_of(folders, shared_folder_uid="SF_U", folder_name="🔐 Secrets"), "U_EMOJI")
        self.assertEqual(self.uid_of(folders, folder_path="Équipe/Données/Clés privées"), "U_DEEP")
        self.assertEqual(
            self.lookup_error(folders, shared_folder_uid="SF_U", folder_name="Donnees"),
            not_found_in("Donnees", "Équipe", "SF_U"))
        self.assertEqual(
            self.lookup_error(folders, shared_folder_uid="SF_U", folder_name="Données 2"),
            'No folder named "Données 2" was found in the folder "Équipe" (UID SF_U).')

    def test_unicode_names_are_not_normalized(self):
        """
        The match is exact, so the decomposed form of a name (NFD) does not find the composed form (NFC). This test
        records that behavior: a playbook must use the same form as the vault.
        """
        folders = [folder("SF_U", "", "Team"), folder("U_FR", "SF_U", unicodedata.normalize("NFC", "Données"))]
        decomposed = unicodedata.normalize("NFD", "Données")
        self.assertNotEqual(decomposed, "Données")
        self.assertEqual(
            self.lookup_error(folders, shared_folder_uid="SF_U", folder_name=decomposed),
            not_found_in(decomposed, "Team", "SF_U"))

    def test_names_with_spaces_match_exactly(self):
        folders = [
            folder("SF_S", "", "Team Vault"),
            folder("S_1", "SF_S", "Web Servers"),
            folder("S_2", "S_1", "Load Balancer Keys"),
        ]
        self.assertEqual(self.uid_of(folders, folder_name="Team Vault"), "SF_S")
        self.assertEqual(self.uid_of(folders, shared_folder_uid="SF_S", folder_name="Web Servers"), "S_1")
        self.assertEqual(self.uid_of(folders, folder_path="Team Vault/Web Servers/Load Balancer Keys"), "S_2")
        # Spaces are part of the name, so they are not trimmed.
        self.assertEqual(
            self.lookup_error(folders, shared_folder_uid="SF_S", folder_name=" Web Servers"),
            not_found_in(" Web Servers", "Team Vault", "SF_S"))
        self.assertEqual(
            self.lookup_error(folders, shared_folder_uid="SF_S", folder_name="Web  Servers"),
            not_found_in("Web  Servers", "Team Vault", "SF_S"))

    def test_folder_name_with_a_slash_is_one_name(self):
        """folder_name is never split, so it can find a folder named "Prod/EU"."""
        self.assertEqual(self.lookup(shared_folder_uid="SF_INFRA", folder_name="Prod/EU"), {
            "folder_uid": "SLASH",
            "folder_name": "Prod/EU",
            "parent_uid": "SF_INFRA",
            "shared_folder_uid": "SF_INFRA",
        })

    def test_folder_name_with_a_slash_does_not_walk_a_path(self):
        """Databases/Production exists as a path, but no single folder has that name."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_name="Databases/Production"),
            not_found_in("Databases/Production", "Infrastructure", "SF_INFRA"))

    def test_blank_folder_name_fails(self):
        """An empty name usually comes from an empty variable. To skip it would return the start folder instead."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_name=""),
            "The folder_name is set but blank. Set it to a folder name, or remove it.")

    def test_folder_name_that_is_a_number_must_be_quoted(self):
        """
        YAML reads an unquoted 2024 as an int, and an unquoted 007 as 7, so str() cannot always give back the text
        that the author wrote. An int fails, also when a folder "2024" exists. The quoted "2024" finds it.
        """
        self.assertEqual(argument_error(self, {"shared_folder_uid": "SF_INFRA", "folder_name": 2024}),
                         type_message("folder_name", "a number (2024)"))
        args = validate({"shared_folder_uid": "SF_INFRA", "folder_name": "2024"})
        self.assertEqual(args["folder_name"], "2024")
        self.assertEqual(self.uid_of(**args), "YEAR")


class KeeperGetFolderPathTest(GetFolderTestCase):
    """folder_path: a walk down one level per name."""

    def test_string_path_is_split_on_slash(self):
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", folder_path="Databases/Production/EU"), "EU")

    def test_single_name_path_is_one_level(self):
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", folder_path="Databases"), "DB")

    def test_multi_level_walk_from_the_top_level(self):
        self.assertEqual(self.lookup(folder_path="Infrastructure/Databases/Production/EU"), {
            "folder_uid": "EU",
            "folder_name": "EU",
            "parent_uid": "PROD",
            "shared_folder_uid": "SF_INFRA",
        })

    def test_walk_takes_the_right_branch_when_names_repeat_at_different_levels(self):
        """Web/Databases and Databases have the same last name, but the path decides which one is found."""
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", folder_path="Web/Databases"), "WEB_DB")
        self.assertEqual(self.uid_of(folder_path="Infrastructure/Databases"), "DB")

    def test_list_path_keeps_a_name_that_contains_a_slash(self):
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", folder_path=["Prod/EU"]), "SLASH")
        self.assertEqual(self.uid_of(folder_path=["Infrastructure", "Prod/EU"]), "SLASH")

    def test_string_path_splits_a_name_that_contains_a_slash(self):
        """As a string, "Prod/EU" is two names, so it cannot find the folder named "Prod/EU"."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_path="Prod/EU"),
            not_found_in("Prod", "Infrastructure", "SF_INFRA"))

    def test_list_path_walks_several_levels(self):
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", folder_path=["Databases", "Production"]), "PROD")

    def test_tuple_path_is_used_like_a_list(self):
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", folder_path=("Databases", "Production")), "PROD")
        self.assertEqual(self.uid_of(folder_path=("Infrastructure", "Prod/EU")), "SLASH")

    def test_int_list_items_fail_and_a_quoted_number_is_a_name(self):
        """
        An int item fails, also when a folder "2024" exists: YAML reads 007 as 7 and 010 as 8, so str() of an int
        is not always the name that the author wrote. The quoted "2024" is a name.
        """
        for kwargs in ({"shared_folder_uid": "SF_INFRA", "folder_path": [2024]},
                       {"folder_path": ["Infrastructure", 2024]}, {"folder_path": ("Infrastructure", 2024)}):
            with self.subTest(**kwargs):
                self.assertEqual(self.lookup_error(**kwargs), path_item_message("a number (2024)"))
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", folder_path=["2024"]), "YEAR")
        self.assertEqual(self.uid_of(folder_path=["Infrastructure", "2024"]), "YEAR")
        self.assertEqual(self.uid_of(folder_path=("Infrastructure", "2024")), "YEAR")
        self.assertEqual(self.uid_of(folder_path="Infrastructure/2024"), "YEAR")

    def test_every_empty_name_is_an_error(self):
        """
        An empty name usually comes from an empty variable or a stray "/". To skip it would silently find a
        different folder, so each form must fail, and the message shows the names as JSON.
        """
        cases = [
            ("/Databases", '["", "Databases"]'),
            ("Databases/", '["Databases", ""]'),
            ("Databases//Production", '["Databases", "", "Production"]'),
            ("/", '["", ""]'),
            ("", '[""]'),
            ([], "[]"),
            ((), "[]"),
            ([""], '[""]'),
            ([None], '[""]'),
            (["Databases", None], '["Databases", ""]'),
            (["Databases", ""], '["Databases", ""]'),
            (("Databases", None), '["Databases", ""]'),
        ]
        for folder_path, names_json in cases:
            with self.subTest(folder_path=folder_path):
                self.assertEqual(
                    self.lookup_error(shared_folder_uid="SF_INFRA", folder_path=folder_path), empty_name(names_json))

    def test_every_empty_name_is_an_error_at_the_top_level(self):
        for folder_path, names_json in (("/Infrastructure", '["", "Infrastructure"]'), ([], "[]"), ([None], '[""]')):
            with self.subTest(folder_path=folder_path):
                self.assertEqual(self.lookup_error(folder_path=folder_path), empty_name(names_json))

    def test_empty_name_fails_even_when_the_other_names_exist(self):
        """Databases/Production exists. With a trailing "/", the lookup must still fail, not return Production."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_path="Databases/Production/"),
            'The folder_path ["Databases", "Production", ""] has an empty folder name. Look for a leading, '
            'trailing, or double "/", or an empty list item.')
        self.assertEqual(
            self.lookup_error(folder_path="/Infrastructure/Databases"),
            empty_name('["", "Infrastructure", "Databases"]'))

    def test_empty_name_message_shows_unicode_names_as_text(self):
        """The JSON in the message keeps non-ASCII names readable, not as \\u escapes."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_path=["Données", ""]),
            'The folder_path ["Données", ""] has an empty folder name. Look for a leading, trailing, or double "/", '
            'or an empty list item.')

    def test_wrong_types_fail(self):
        for folder_path in ({"name": "Databases"}, 2024, 20.24, True, b"Databases", {"Databases"}):
            with self.subTest(folder_path=folder_path):
                self.assertEqual(self.lookup_error(shared_folder_uid="SF_INFRA", folder_path=folder_path),
                                 WRONG_PATH_TYPE)

    def test_list_items_that_are_not_names_fail(self):
        """
        str() would turn yes into "True", 1.10 into "1.1", and 007 into "7", so these items must fail. The tree has
        folders with those names, so an item that str() changed would find a folder instead of failing.
        """
        cases = [
            (True, "a boolean (True)"),
            (False, "a boolean (False)"),
            (1.1, "a number (1.1)"),
            (2024, "a number (2024)"),
            (7, "a number (7)"),
            ({"name": "Production"}, "a dictionary"),
            (["Production"], "a list"),
            (("Production",), "a list"),
            ({"Production"}, "a list"),
            (frozenset({"Production"}), "a list"),
            (b"Production", "a byte string"),
            (bytearray(b"Production"), "a byte string"),
            (datetime.date(2026, 9, 29), "a date (2026-09-29)"),
            (datetime.datetime(2026, 9, 29, 10, 0), "a date and time (2026-09-29 10:00:00)"),
            (decimal.Decimal("20.24"), "a value of type Decimal"),
        ]
        folders = standard_folders() + [folder("TRUE", "DB", "True"), folder("ONE", "DB", "1.1"),
                                        folder("DB_2024", "DB", "2024"), folder("SEVEN", "DB", "7"),
                                        folder("DAY", "DB", "2026-09-29"), folder("DEC", "DB", "20.24")]
        for value, kind in cases:
            with self.subTest(value=value):
                self.assertEqual(
                    self.lookup_error(folders, shared_folder_uid="SF_INFRA", folder_path=["Databases", value]),
                    path_item_message(kind))
                self.assertEqual(self.lookup_error(folders, folder_path=("Infrastructure", "Databases", value)),
                                 path_item_message(kind))

    def test_yaml_list_items_that_would_change_silently_fail(self):
        """
        YAML reads each unquoted item as another type, and for most of them str() gives other text: 007 is 7, 010
        is 8, 0x1F is 31, and 2026-9-29 10:00:00 is 2026-09-29 10:00:00. A date keeps its text, but it still fails.
        """
        folders = standard_folders() + [folder("TRUE", "DB", "True"), folder("ONE", "DB", "1.1"),
                                        folder("SEVEN", "DB", "7"), folder("EIGHT", "DB", "8"),
                                        folder("DAY", "DB", "2026-09-29")]
        cases = [
            ("[Databases, yes]", "a boolean (True)"),
            ("[Databases, 1.10]", "a number (1.1)"),
            ("[Databases, 007]", "a number (7)"),
            ("[Databases, 010]", "a number (8)"),
            ("[Databases, 1_000]", "a number (1000)"),
            ("[Databases, 0x1F]", "a number (31)"),
            ("[Databases, 2026-09-29]", "a date (2026-09-29)"),
            ("[Databases, 2026-9-29 10:00:00]", "a date and time (2026-09-29 10:00:00)"),
        ]
        for text, kind in cases:
            with self.subTest(yaml=text):
                self.assertEqual(
                    self.lookup_error(folders, shared_folder_uid="SF_INFRA", folder_path=yaml.safe_load(text)),
                    path_item_message(kind))

    def test_a_none_item_is_still_an_empty_name_and_not_a_type_error(self):
        self.assertEqual(self.lookup_error(shared_folder_uid="SF_INFRA", folder_path=["Databases", None]),
                         empty_name('["Databases", ""]'))
        self.assertEqual(self.lookup_error(shared_folder_uid="SF_INFRA", folder_path=[None]), empty_name('[""]'))

    def test_missing_level_in_the_middle_names_the_folder_where_the_walk_stopped(self):
        """The error names the last folder that was found, with its full path, so the user can see where it broke."""
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_path="Databases/Nope/EU"),
            not_found_in("Nope", "Infrastructure/Databases", "DB"))
        self.assertEqual(
            self.lookup_error(folder_path="Infrastructure/Databases/Production/Nope/Frankfurt"),
            not_found_in("Nope", "Infrastructure/Databases/Production", "PROD"))

    def test_missing_level_below_a_subfolder_start_shows_the_path_from_the_shared_folder(self):
        self.assertEqual(
            self.lookup_error(subfolder_uid="PROD", folder_path="EU/Nope"),
            not_found_in("Nope", "Infrastructure/Databases/Production/EU", "EU"))

    def test_missing_first_level(self):
        self.assertEqual(self.lookup_error(folder_path="Nope/Databases"), not_found_at_top("Nope"))
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_path="Nope/Production"),
            not_found_in("Nope", "Infrastructure", "SF_INFRA"))

    def test_missing_last_level(self):
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_path="Databases/Production/Nope"),
            not_found_in("Nope", "Infrastructure/Databases/Production", "PROD"))

    def test_duplicates_in_the_middle_of_a_path_fail_and_never_pick_one(self):
        """
        Only the second "Dup" has a "Leaf". A lookup that tried each duplicate could find it, but the module must
        not guess: it fails at "Dup" and lists every duplicate.
        """
        expected = duplicates_in("Dup", "Applications", "SF_APPS", ["DUP_1", "DUP_2", "DUP_3"])
        self.assertEqual(self.lookup_error(shared_folder_uid="SF_APPS", folder_path="Dup/Leaf"), expected)
        self.assertEqual(self.lookup_error(folder_path="Applications/Dup/Leaf"), expected)
        self.assertEqual(self.lookup_error(folder_path=["Applications", "Dup", "Leaf"]), expected)

    def test_duplicates_at_the_first_level_of_a_top_level_path(self):
        self.assertEqual(
            self.lookup_error(folder_path="Team/Anything"), duplicates_at_top("Team", ["SF_TEAM_1", "SF_TEAM_2"]))

    def test_a_path_below_a_duplicate_can_start_at_the_duplicate_uid(self):
        """The fix that the duplicate error suggests: start at the UID of the wanted duplicate."""
        self.assertEqual(self.uid_of(subfolder_uid="DUP_2", folder_path="Leaf"), "LEAF")
        self.assertEqual(self.uid_of(shared_folder_uid="SF_TEAM_2"), "SF_TEAM_2")


class KeeperGetFolderInputValidationTest(GetFolderTestCase):
    """Checks on the options themselves. None of them needs the folder list."""

    def make_keeper_without_folders(self):
        keeper = self.make_keeper()
        keeper.client.get_folders.side_effect = AssertionError("get_folders must not be needed to find this error")
        return keeper

    def test_folder_name_and_folder_path_both_set_fail(self):
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_name="Databases", folder_path="Databases"),
            "The folder_name and folder_path are both set. Set only one of them.")

    def test_blank_optional_uids_fail_without_the_folder_list(self):
        """A blank UID usually comes from an empty variable. It must fail, not act as if the option were not set."""
        for option in ("shared_folder_uid", "subfolder_uid"):
            for value in ("", "   ", "\t", "\n"):
                with self.subTest(option=option, value=value):
                    keeper = self.make_keeper_without_folders()
                    message = self.call_error(keeper, **{option: value, "folder_name": "Databases"})
                    self.assertEqual(
                        message, "The {} is set but blank. Set it to a folder UID, or remove it.".format(option))
                    keeper.client.get_folders.assert_not_called()

    def test_blank_uid_with_no_name_is_blank_not_nothing_to_look_up(self):
        keeper = self.make_keeper_without_folders()
        self.assertEqual(
            self.call_error(keeper, shared_folder_uid=""),
            "The shared_folder_uid is set but blank. Set it to a folder UID, or remove it.")
        keeper.client.get_folders.assert_not_called()

    def test_uids_with_leading_or_trailing_whitespace_fail_without_the_folder_list(self):
        for option in ("shared_folder_uid", "subfolder_uid"):
            for value in (" ABC", "ABC\n", "ABC ", "\tABC", " ABC "):
                with self.subTest(option=option, value=value):
                    keeper = self.make_keeper_without_folders()
                    message = self.call_error(keeper, **{option: value})
                    self.assertEqual(
                        message, "The {} {!r} has leading or trailing whitespace.".format(option, value))
                    keeper.client.get_folders.assert_not_called()

    def test_whitespace_message_shows_the_value_with_repr(self):
        """A newline is shown as \\n, so the user can see it. A plain format would print an invisible line break."""
        keeper = self.make_keeper_without_folders()
        self.assertEqual(
            self.call_error(keeper, shared_folder_uid="ABC\n"),
            "The shared_folder_uid 'ABC\\n' has leading or trailing whitespace.")
        self.assertEqual(
            self.call_error(keeper, subfolder_uid=" ABC"),
            "The subfolder_uid ' ABC' has leading or trailing whitespace.")

    def test_padded_uid_of_a_real_folder_is_an_error_not_a_match(self):
        """
        " SF_INFRA" must not be trimmed into a match, and must not report "not found": the user must fix the
        variable that added the whitespace.
        """
        for kwargs in ({"shared_folder_uid": " SF_INFRA"}, {"shared_folder_uid": "SF_INFRA\n"},
                       {"subfolder_uid": "DB "}, {"shared_folder_uid": "SF_INFRA", "subfolder_uid": "\tDB"}):
            with self.subTest(**kwargs):
                message = self.lookup_error(**kwargs)
                self.assertIn("has leading or trailing whitespace.", message)
                self.assertNotIn("was not found", message)

    def test_nothing_to_look_up(self):
        self.assertEqual(self.lookup_error(), NOTHING_TO_LOOK_UP)
        self.assertEqual(self.lookup_error(include_subfolders=True), NOTHING_TO_LOOK_UP)
        self.assertEqual(
            self.lookup_error(shared_folder_uid=None, subfolder_uid=None, folder_name=None, folder_path=None),
            NOTHING_TO_LOOK_UP)


class KeeperGetFolderResultTest(GetFolderTestCase):
    """The shape of the result dictionary."""

    ORDER_FOLDERS = [
        folder("ROOT", "", "Root"),
        folder("C2_1", "C2", "Under Alpha"),
        folder("C1", "ROOT", "Zulu"),
        folder("C2", "ROOT", "Alpha"),
        folder("C1_1", "C1", "Mike"),
        folder("OTHER", "", "Other"),
        folder("C3", "ROOT", "Mike"),
        folder("C1_1_1", "C1_1", "Deep"),
        folder("OTHER_1", "OTHER", "Not Below Root"),
        folder("C1_2", "C1", "Bravo"),
    ]

    def test_result_has_exactly_the_documented_keys_without_subfolders(self):
        for kwargs in ({"shared_folder_uid": "SF_INFRA"}, {"subfolder_uid": "EU"},
                       {"folder_path": "Infrastructure/Web"}, {"folder_name": "Applications"}):
            with self.subTest(**kwargs):
                result = self.lookup(**kwargs)
                self.assertEqual(set(result), {"folder_uid", "folder_name", "parent_uid", "shared_folder_uid"})

    def test_subfolders_key_is_absent_when_include_subfolders_is_false(self):
        """Absent, not an empty list, so a playbook cannot mistake "not asked" for "no subfolders"."""
        self.assertNotIn("subfolders", self.lookup(shared_folder_uid="SF_INFRA"))
        self.assertNotIn("subfolders", self.lookup(shared_folder_uid="SF_INFRA", include_subfolders=False))

    def test_result_has_the_subfolders_key_when_include_subfolders_is_true(self):
        result = self.lookup(shared_folder_uid="SF_INFRA", include_subfolders=True)
        self.assertEqual(
            set(result), {"folder_uid", "folder_name", "parent_uid", "shared_folder_uid", "subfolders"})

    def test_parent_uid_is_an_empty_string_for_a_shared_folder(self):
        self.assertEqual(self.lookup(shared_folder_uid="SF_APPS")["parent_uid"], "")
        self.assertEqual(self.lookup(shared_folder_uid="SF_TEAM_1")["parent_uid"], "")
        self.assertEqual(self.lookup(folder_name="Applications")["parent_uid"], "")

    def test_shared_folder_uid_of_a_shared_folder_is_its_own_uid(self):
        self.assertEqual(self.lookup(folder_name="Applications")["shared_folder_uid"], "SF_APPS")

    def test_shared_folder_uid_of_a_subfolder(self):
        self.assertEqual(self.lookup(shared_folder_uid="SF_APPS", folder_name="Services")["shared_folder_uid"],
                         "SF_APPS")

    def test_shared_folder_uid_of_a_deep_subfolder_is_the_top_level_ancestor(self):
        """Not the parent: Frankfurt is four levels down, and its shared folder is Infrastructure."""
        result = self.lookup(subfolder_uid="FRA")
        self.assertEqual(result["parent_uid"], "EU")
        self.assertEqual(result["shared_folder_uid"], "SF_INFRA")
        self.assertEqual(self.lookup(subfolder_uid="LEAF")["shared_folder_uid"], "SF_APPS")

    def test_subfolders_of_a_shared_folder_are_every_folder_below_it(self):
        result = self.lookup(shared_folder_uid="SF_INFRA", include_subfolders=True)
        self.assertEqual(result["subfolders"], [
            item("DB", "Databases", "SF_INFRA"),
            item("PROD", "Production", "DB"),
            item("EU", "EU", "PROD"),
            item("FRA", "Frankfurt", "EU"),
            item("STG", "Staging", "DB"),
            item("WEB", "Web", "SF_INFRA"),
            item("WEB_DB", "Databases", "WEB"),
            item("SLASH", "Prod/EU", "SF_INFRA"),
            item("YEAR", "2024", "SF_INFRA"),
        ])

    def test_subfolders_are_depth_first_with_children_in_get_folders_order(self):
        """
        The list order of get_folders is not the tree order here: a grandchild comes before its parent, and the
        names are not sorted. The result must be depth-first, each parent before its children, and siblings in
        the order that get_folders returned them.
        """
        result = self.lookup(self.ORDER_FOLDERS, shared_folder_uid="ROOT", include_subfolders=True)
        self.assertEqual(result["subfolders"], [
            item("C1", "Zulu", "ROOT"),
            item("C1_1", "Mike", "C1"),
            item("C1_1_1", "Deep", "C1_1"),
            item("C1_2", "Bravo", "C1"),
            item("C2", "Alpha", "ROOT"),
            item("C2_1", "Under Alpha", "C2"),
            item("C3", "Mike", "ROOT"),
        ])

    def test_every_parent_comes_before_its_children(self):
        for kwargs in ({"shared_folder_uid": "ROOT"}, {"subfolder_uid": "C1"}):
            with self.subTest(**kwargs):
                result = self.lookup(self.ORDER_FOLDERS, include_subfolders=True, **kwargs)
                seen = {result["folder_uid"]}
                for entry in result["subfolders"]:
                    self.assertIn(entry["parent_uid"], seen, "a folder came before its parent: {}".format(entry))
                    seen.add(entry["folder_uid"])

    def test_subfolders_of_a_subfolder_do_not_include_the_folder_itself_or_other_branches(self):
        result = self.lookup(self.ORDER_FOLDERS, subfolder_uid="C1", include_subfolders=True)
        self.assertEqual([entry["folder_uid"] for entry in result["subfolders"]], ["C1_1", "C1_1_1", "C1_2"])

    def test_subfolders_of_a_leaf_is_an_empty_list(self):
        result = self.lookup(subfolder_uid="FRA", include_subfolders=True)
        self.assertIn("subfolders", result)
        self.assertEqual(result["subfolders"], [])

    def test_subfolders_of_a_folder_found_by_path(self):
        result = self.lookup(folder_path="Applications/Dup", include_subfolders=True,
                             folders=[folder("SF_APPS", "", "Applications"), folder("ONE", "SF_APPS", "Dup"),
                                      folder("ONE_1", "ONE", "Child")])
        self.assertEqual(result["subfolders"], [item("ONE_1", "Child", "ONE")])

    def test_each_subfolder_entry_has_exactly_three_keys(self):
        result = self.lookup(shared_folder_uid="SF_APPS", include_subfolders=True)
        self.assertEqual(len(result["subfolders"]), 5)
        for entry in result["subfolders"]:
            self.assertEqual(set(entry), {"folder_uid", "folder_name", "parent_uid"})

    def test_subfolders_include_same_named_siblings(self):
        """Duplicate names fail a lookup by name, but the subfolder list must still show all of them."""
        result = self.lookup(shared_folder_uid="SF_APPS", include_subfolders=True)
        self.assertEqual(result["subfolders"], [
            item("DUP_1", "Dup", "SF_APPS"),
            item("DUP_2", "Dup", "SF_APPS"),
            item("LEAF", "Leaf", "DUP_2"),
            item("DUP_3", "Dup", "SF_APPS"),
            item("SVC", "Services", "SF_APPS"),
        ])


class KeeperGetFolderMalformedDataTest(GetFolderTestCase):
    """
    A bad server response must not hang the task or crash it with a Python error. Every call here has a time
    limit, so a missing loop guard fails the test instead of stopping the test run.
    """

    CYCLE = [folder("SF", "", "Shared"), folder("A", "B", "Alpha"), folder("B", "A", "Bravo")]

    def test_parent_cycle_lookup_by_uid_returns_without_a_shared_folder(self):
        self.assertEqual(self.lookup(self.CYCLE, subfolder_uid="A"), {
            "folder_uid": "A",
            "folder_name": "Alpha",
            "parent_uid": "B",
            "shared_folder_uid": None,
        })

    def test_parent_cycle_subfolders_list_each_folder_once(self):
        result = self.lookup(self.CYCLE, subfolder_uid="A", include_subfolders=True)
        self.assertEqual(result["subfolders"], [item("B", "Bravo", "A")])

    def test_parent_cycle_in_an_error_label_does_not_hang(self):
        """The error label walks the parent chain to build the path. On a cycle it must stop."""
        message = self.lookup_error(self.CYCLE, subfolder_uid="A", folder_name="Nope")
        self.assertTrue(message.startswith('No folder named "Nope" was found in the folder "'), message)
        self.assertTrue(message.endswith("(UID A)."), message)

    def test_parent_cycle_with_shared_folder_uid_is_not_inside(self):
        message = self.lookup_error(self.CYCLE, shared_folder_uid="SF", subfolder_uid="A")
        self.assertIn("is not inside the shared folder \"Shared\" (UID SF).", message)

    def test_parent_cycle_is_not_at_the_top_level(self):
        self.assertEqual(self.lookup_error(self.CYCLE, folder_name="Alpha"), not_found_at_top("Alpha"))

    def test_name_walk_through_a_parent_cycle_ends(self):
        result = self.lookup(self.CYCLE, subfolder_uid="A", folder_path=["Bravo", "Alpha", "Bravo"])
        self.assertEqual(result["folder_uid"], "B")
        self.assertIsNone(result["shared_folder_uid"])

    def test_three_folder_cycle(self):
        folders = [folder("A", "C", "A"), folder("B", "A", "B"), folder("C", "B", "C")]
        result = self.lookup(folders, subfolder_uid="A", include_subfolders=True)
        self.assertIsNone(result["shared_folder_uid"])
        self.assertEqual([entry["folder_uid"] for entry in result["subfolders"]], ["B", "C"])

    def test_self_parent(self):
        folders = [folder("SF", "", "Shared"), folder("X", "X", "Loop")]
        result = self.lookup(folders, subfolder_uid="X", include_subfolders=True)
        self.assertEqual(result, {
            "folder_uid": "X",
            "folder_name": "Loop",
            "parent_uid": "X",
            "shared_folder_uid": None,
            "subfolders": [],
        })
        self.assertIn("is not inside", self.lookup_error(folders, shared_folder_uid="SF", subfolder_uid="X"))

    def test_self_parent_shared_folder_uid_is_a_subfolder(self):
        folders = [folder("X", "X", "Loop")]
        self.assertIn("is a subfolder, not a shared folder", self.lookup_error(folders, shared_folder_uid="X"))

    def test_subfolder_whose_parent_is_missing(self):
        """The parent is not shared to the application, so the chain is broken: shared_folder_uid is None."""
        folders = [folder("SF", "", "Shared"), folder("ORPHAN", "GONE", "Orphan"),
                   folder("ORPHAN_CHILD", "ORPHAN", "Child")]
        self.assertEqual(self.lookup(folders, subfolder_uid="ORPHAN", include_subfolders=True), {
            "folder_uid": "ORPHAN",
            "folder_name": "Orphan",
            "parent_uid": "GONE",
            "shared_folder_uid": None,
            "subfolders": [item("ORPHAN_CHILD", "Child", "ORPHAN")],
        })
        self.assertIsNone(self.lookup(folders, subfolder_uid="ORPHAN", folder_name="Child")["shared_folder_uid"])

    def test_subfolder_whose_parent_is_missing_is_not_inside_a_shared_folder(self):
        folders = [folder("SF", "", "Shared"), folder("ORPHAN", "GONE", "Orphan")]
        self.assertEqual(
            self.lookup_error(folders, shared_folder_uid="SF", subfolder_uid="ORPHAN"),
            'The subfolder "Orphan" (UID ORPHAN) is not inside the shared folder "Shared" (UID SF).')

    def test_cycle_inside_the_subtree_walk(self):
        """
        L1 is listed twice, the second time as a child of its own child L2. A walk down the tree without a
        visited check would loop between L1 and L2.
        """
        folders = [folder("SF", "", "Shared"), folder("L1", "SF", "Level 1"), folder("L2", "L1", "Level 2"),
                   folder("L1", "L2", "Level 1 again")]
        result = self.lookup(folders, shared_folder_uid="SF", include_subfolders=True)
        self.assertEqual(result["subfolders"], [item("L1", "Level 1", "SF"), item("L2", "Level 2", "L1")])
        deep = self.lookup(folders, folder_path="Shared/Level 1/Level 2", include_subfolders=True)
        self.assertEqual(deep["folder_uid"], "L2")
        self.assertEqual(deep["shared_folder_uid"], "SF")
        self.assertEqual([entry["folder_uid"] for entry in deep["subfolders"]], ["L1"])


class KeeperGetFolderQuotingTest(GetFolderTestCase):
    """
    Folder names in messages are JSON-quoted. A newline, a tab, a double quote, or a backslash in a name shows as
    an escape, so that a stray character from a template or a file is visible in the error.
    """

    FOLDERS = [
        folder("SF_INFRA", "", "Infrastructure"),
        folder("QUOTE", "SF_INFRA", 'Say "hi"'),
        folder("TWIN_1", "SF_INFRA", 'Twin "A"'),
        folder("TWIN_2", "SF_INFRA", 'Twin "A"'),
        folder("NL_1", "SF_INFRA", "Line\nBreak"),
        folder("NL_2", "SF_INFRA", "Line\nBreak"),
        folder("OPS", "SF_INFRA", 'Ops "EU"\t'),
        folder("OPS_KEYS", "OPS", "Keys"),
        folder("WINDOWS", "SF_INFRA", "C:\\Temp"),
        folder("SF_TAB_1", "", "Team\t"),
        folder("SF_TAB_2", "", "Team\t"),
    ]

    def missing(self, **kwargs):
        return self.lookup_error(self.FOLDERS, **kwargs)

    def test_a_newline_in_a_missing_name_is_escaped(self):
        message = self.missing(shared_folder_uid="SF_INFRA", folder_name="Databases\n")
        self.assertEqual(message,
                         'No folder named "Databases\\n" was found in the folder "Infrastructure" (UID SF_INFRA).')
        self.assertNotIn("\n", message)

    def test_a_tab_in_a_missing_name_is_escaped(self):
        message = self.missing(shared_folder_uid="SF_INFRA", folder_path=["Data\tbases"])
        self.assertEqual(message,
                         'No folder named "Data\\tbases" was found in the folder "Infrastructure" (UID SF_INFRA).')
        self.assertNotIn("\t", message)

    def test_a_double_quote_in_a_missing_name_is_escaped(self):
        self.assertEqual(
            self.missing(shared_folder_uid="SF_INFRA", folder_name='No "such" folder'),
            'No folder named "No \\"such\\" folder" was found in the folder "Infrastructure" (UID SF_INFRA).')

    def test_a_backslash_in_a_missing_name_is_escaped(self):
        self.assertEqual(
            self.missing(shared_folder_uid="SF_INFRA", folder_name="C:\\Tmp"),
            'No folder named "C:\\\\Tmp" was found in the folder "Infrastructure" (UID SF_INFRA).')

    def test_non_ascii_names_are_not_escaped(self):
        self.assertEqual(
            self.missing(shared_folder_uid="SF_INFRA", folder_name="🔐 Données"),
            'No folder named "🔐 Données" was found in the folder "Infrastructure" (UID SF_INFRA).')

    def test_names_with_special_characters_still_match_exactly(self):
        self.assertEqual(self.uid_of(self.FOLDERS, shared_folder_uid="SF_INFRA", folder_name='Say "hi"'), "QUOTE")
        self.assertEqual(self.uid_of(self.FOLDERS, shared_folder_uid="SF_INFRA", folder_name="C:\\Temp"), "WINDOWS")
        self.assertEqual(self.uid_of(self.FOLDERS, folder_path=["Infrastructure", 'Ops "EU"\t', "Keys"]), "OPS_KEYS")

    def test_duplicate_names_with_a_double_quote_are_escaped_in_both_places(self):
        self.assertEqual(
            self.missing(shared_folder_uid="SF_INFRA", folder_name='Twin "A"'),
            'Found 2 folders named "Twin \\"A\\"" in the folder "Infrastructure" (UID SF_INFRA): TWIN_1, TWIN_2. '
            'Rename one of them in the vault. Or set subfolder_uid to the UID of the folder that you want, and '
            'remove "Twin \\"A\\"" from folder_name or folder_path.')

    def test_duplicate_names_with_a_newline_are_escaped_in_both_places(self):
        message = self.missing(folder_path=["Infrastructure", "Line\nBreak"])
        self.assertEqual(
            message,
            'Found 2 folders named "Line\\nBreak" in the folder "Infrastructure" (UID SF_INFRA): NL_1, NL_2. Rename '
            'one of them in the vault. Or set subfolder_uid to the UID of the folder that you want, and remove '
            '"Line\\nBreak" from folder_name or folder_path.')
        self.assertNotIn("\n", message)

    def test_duplicate_shared_folder_names_with_a_tab_are_escaped(self):
        self.assertEqual(
            self.missing(folder_name="Team\t"),
            'Found 2 folders named "Team\\t" at the top level (the shared folders of this KSM application): '
            'SF_TAB_1, SF_TAB_2. Rename one of them in the vault. Or set shared_folder_uid to the UID of the folder '
            'that you want, and remove "Team\\t" from folder_name or folder_path.')

    def test_the_folder_label_escapes_special_characters_in_the_path(self):
        message = self.missing(subfolder_uid="OPS", folder_name="Nope")
        self.assertEqual(
            message, 'No folder named "Nope" was found in the folder "Infrastructure/Ops \\"EU\\"\\t" (UID OPS).')
        self.assertNotIn("\t", message)

    def test_the_subfolder_and_not_inside_labels_escape_special_characters(self):
        self.assertEqual(
            self.missing(shared_folder_uid="QUOTE"),
            'The folder "Infrastructure/Say \\"hi\\"" (UID QUOTE) is a subfolder, not a shared folder. Set it as '
            'subfolder_uid instead.')
        self.assertEqual(
            self.missing(shared_folder_uid="SF_TAB_1", subfolder_uid="OPS_KEYS"),
            'The subfolder "Infrastructure/Ops \\"EU\\"\\t/Keys" (UID OPS_KEYS) is not inside the shared folder '
            '"Team\\t" (UID SF_TAB_1).')


class KeeperGetFolderSdkTest(GetFolderTestCase):
    """How the module handles the SDK's get_folders()."""

    def test_get_folders_error_becomes_keeper_folder_error(self):
        keeper = self.make_keeper()
        keeper.client.get_folders.side_effect = KeeperError("Signature is invalid")
        self.assertEqual(self.call_error(keeper, shared_folder_uid="SF_INFRA"),
                         "Cannot get folders: Signature is invalid")

    def test_any_get_folders_exception_becomes_keeper_folder_error(self):
        keeper = self.make_keeper()
        keeper.client.get_folders.side_effect = ConnectionError("connection reset")
        self.assertEqual(self.call_error(keeper, folder_path="Infrastructure/Databases"),
                         "Cannot get folders: connection reset")

    def test_get_folders_method_returns_the_client_list(self):
        keeper = self.make_keeper()
        self.assertIs(keeper.get_folders(), keeper.client.get_folders.return_value)

    def test_get_folders_none_is_an_empty_list(self):
        """The SDK can return None. That must mean "no folders", not a TypeError."""
        keeper = self.make_keeper()
        keeper.client.get_folders.return_value = None
        self.assertEqual(keeper.get_folders(), [])
        for kwargs, expected in (
                ({"shared_folder_uid": "SF_INFRA"},
                 "The shared folder SF_INFRA was not found, or it is not shared to this KSM application."),
                ({"subfolder_uid": "DB"},
                 "The subfolder DB was not found, or it is not shared to this KSM application."),
                ({"folder_name": "Infrastructure"}, not_found_at_top("Infrastructure")),
                ({"folder_path": ["Infrastructure", "Databases"]}, not_found_at_top("Infrastructure"))):
            with self.subTest(**kwargs):
                keeper = self.make_keeper()
                keeper.client.get_folders.return_value = None
                self.assertEqual(self.call_error(keeper, **kwargs), expected)

    def test_get_folders_empty_list(self):
        self.assertEqual(self.lookup_error([], folder_name="Infrastructure"), not_found_at_top("Infrastructure"))


class KeeperGetFolderReadOnlyTest(GetFolderTestCase):
    """A lookup must never change the vault, and it must not read the records."""

    LOOKUPS = [
        {"shared_folder_uid": "SF_INFRA"},
        {"shared_folder_uid": "SF_INFRA", "folder_name": "Databases"},
        {"folder_path": "Infrastructure/Databases/Production", "include_subfolders": True},
        {"subfolder_uid": "PROD", "folder_path": ["EU"], "include_subfolders": True},
        {"shared_folder_uid": "SF_INFRA", "folder_name": "Nope"},
        {"shared_folder_uid": "SF_APPS", "folder_name": "Dup"},
        {"shared_folder_uid": "SF_APPS", "subfolder_uid": "PROD"},
        {"shared_folder_uid": "DB"},
        {"folder_name": "Team"},
    ]

    def test_only_get_folders_is_called(self):
        for kwargs in self.LOOKUPS:
            with self.subTest(**kwargs):
                keeper = self.make_keeper()
                try:
                    self.call(keeper, **kwargs)
                except KeeperFolderError:
                    pass
                names = [name for name, _args, _kwargs in keeper.client.method_calls]
                self.assertEqual(set(names), {"get_folders"}, "unexpected SDK calls: {}".format(names))
                for method in ("create_folder", "update_folder", "delete_folder", "get_secrets", "create_secret",
                               "save", "delete_secret"):
                    getattr(keeper.client, method).assert_not_called()

    def test_the_folder_objects_are_not_changed(self):
        folders = standard_folders()
        before = [(f.folder_uid, f.parent_uid, f.name, f.folder_key) for f in folders]
        self.lookup(folders, shared_folder_uid="SF_INFRA", include_subfolders=True)
        self.lookup(folders, folder_path="Infrastructure/Databases/Production/EU")
        self.assertEqual([(f.folder_uid, f.parent_uid, f.name, f.folder_key) for f in folders], before)


class KeeperGetFolderArgumentSpecTest(unittest.TestCase):
    """validate_task_args with the module's ARGUMENT_SPEC: the checks that run before any connection."""

    def test_argument_spec_matches_the_contract(self):
        self.assertEqual(action_plugin().ActionModule.ARGUMENT_SPEC, {
            "shared_folder_uid": {"type": "str"},
            "subfolder_uid": {"type": "str"},
            "folder_name": {"type": "str"},
            "folder_path": {"type": "raw"},
            "include_subfolders": {"type": "bool", "default": False},
        })

    def test_unknown_option_fails(self):
        """A typo must fail. If it were ignored, the lookup could silently return the start folder."""
        message = argument_error(self, {"shared_folder_uid": "SF_INFRA", "folder_nmae": "Databases"})
        self.assertTrue(message.startswith(UNSUPPORTED_PREFIX + "folder_nmae" + SUPPORTED_SEPARATOR), message)
        self.assertEqual(unsupported_names(message), ({"folder_nmae"}, SUPPORTED_OPTION_NAMES))

    def test_every_unknown_option_is_named(self):
        message = argument_error(self, {"folder_nmae": "Databases", "shared_folder": "SF_INFRA"})
        self.assertEqual(unsupported_names(message), ({"folder_nmae", "shared_folder"}, SUPPORTED_OPTION_NAMES))

    def test_folder_name_and_folder_path_are_mutually_exclusive(self):
        self.assertEqual(
            argument_error(self, {"folder_name": "Databases", "folder_path": "Databases"}),
            "parameters are mutually exclusive: folder_name|folder_path")

    def test_validator_messages_are_joined_with_a_semicolon(self):
        """
        Two validator errors. The first one does not end with a period, so "; " follows it. The validator reports
        the exclusive pair first on ansible-core 2.12, 2.15, and 2.21.
        """
        message = argument_error(self, {"folder_name": "Databases", "folder_path": "Databases", "folder_nmae": "x"})
        exclusive = "parameters are mutually exclusive: folder_name|folder_path"
        self.assertTrue(message.startswith(exclusive + "; " + UNSUPPORTED_PREFIX), message)
        self.assertEqual(unsupported_names(message[len(exclusive) + 2:]), ({"folder_nmae"}, SUPPORTED_OPTION_NAMES))

    def test_include_subfolders_yes_and_no_become_booleans(self):
        for value, expected in (("yes", True), ("no", False), ("true", True), ("false", False), (True, True),
                                (False, False)):
            with self.subTest(value=value):
                self.assertIs(validate({"shared_folder_uid": "SF", "include_subfolders": value})["include_subfolders"],
                              expected)

    def test_include_subfolders_that_is_not_a_boolean_fails(self):
        message = argument_error(self, {"shared_folder_uid": "SF", "include_subfolders": "maybe"})
        self.assertTrue(message.startswith("argument 'include_subfolders' is of type "), message)
        self.assertIn("The value 'maybe' is not a valid boolean.", message)
        self.assertNotIn("; ", message)

    def test_defaults_are_filled_in(self):
        self.assertEqual(validate({}), {
            "shared_folder_uid": None,
            "subfolder_uid": None,
            "folder_name": None,
            "folder_path": None,
            "include_subfolders": False,
        })
        self.assertIs(validate({"shared_folder_uid": "SF"})["include_subfolders"], False)

    def test_folder_path_is_raw_and_keeps_its_type(self):
        self.assertEqual(validate({"folder_path": ["Infrastructure", 2024]})["folder_path"], ["Infrastructure", 2024])
        self.assertEqual(validate({"folder_path": "Infrastructure/2024"})["folder_path"], "Infrastructure/2024")

    def test_validated_arguments_work_with_get_folder(self):
        keeper = object.__new__(KeeperAnsible)
        keeper.client = MagicMock()
        keeper.client.get_folders.return_value = standard_folders()
        args = validate({"folder_path": ["Infrastructure", "2024"], "include_subfolders": "yes"})
        result = keeper.get_folder(**args)
        self.assertEqual(result["folder_uid"], "YEAR")
        self.assertEqual(result["subfolders"], [])


class KeeperGetFolderNullOptionTest(unittest.TestCase):
    """
    A template variable with no value gives null. Null must fail, not mean "not set": as "not set", a lookup
    would silently start at a different folder, or return the start folder instead of a subfolder.
    """

    OPTIONS = ["folder_name", "folder_path", "include_subfolders", "shared_folder_uid", "subfolder_uid"]

    def test_each_option_set_to_null_fails(self):
        for option in self.OPTIONS:
            with self.subTest(option=option):
                self.assertEqual(argument_error(self, {option: None}), null_message(option))

    def test_null_fails_next_to_valid_options(self):
        """The two cases where null as "not set" gave a wrong folder with no error."""
        self.assertEqual(argument_error(self, {"shared_folder_uid": None, "folder_name": "Infrastructure"}),
                         null_message("shared_folder_uid"))
        self.assertEqual(argument_error(self, {"shared_folder_uid": "SF_INFRA", "folder_name": None}),
                         null_message("folder_name"))

    def test_every_null_option_is_named_in_sorted_order(self):
        """Each null message ends with a period, so a space separates them."""
        args = {option: None for option in reversed(self.OPTIONS)}
        self.assertEqual(argument_error(self, args), " ".join(null_message(option) for option in self.OPTIONS))

    def test_null_is_reported_without_the_validator_messages(self):
        """The pre-checks run first. When one fails, the validator does not run, so its errors are not added."""
        self.assertEqual(argument_error(self, {"folder_name": None, "folder_nmae": "Databases"}),
                         null_message("folder_name"))
        self.assertEqual(argument_error(self, {"folder_name": None, "folder_path": "Databases"}),
                         null_message("folder_name"))
        self.assertEqual(argument_error(self, {"include_subfolders": None, "folder_nmae": "x"}),
                         null_message("include_subfolders"))

    def test_an_omitted_option_is_still_not_set(self):
        args = validate({"shared_folder_uid": "SF_INFRA"})
        self.assertIsNone(args["folder_name"])
        self.assertIsNone(args["subfolder_uid"])


class KeeperGetFolderOptionTypeTest(unittest.TestCase):
    """
    ArgumentSpecValidator turns any value of a str option into a string with no warning: a list becomes
    "['a', 'b']", yes becomes "True", and 1.10 becomes "1.1". YAML also changes the text of some numbers that have
    no quotes: 007 becomes 7, and 010 becomes 8. For a UID or a folder name, that is a different value, so every
    value that is not a string fails. A quoted value stays exactly as the author wrote it.
    """

    STR_OPTIONS = ["folder_name", "shared_folder_uid", "subfolder_uid"]
    VALUES = [
        (["Databases"], "a list"),
        (("Databases",), "a list"),
        ({"Databases"}, "a list"),
        (frozenset({"Databases"}), "a list"),
        ({"name": "Databases"}, "a dictionary"),
        (True, "a boolean (True)"),
        (False, "a boolean (False)"),
        (1.1, "a number (1.1)"),
        (20.24, "a number (20.24)"),
        (2024, "a number (2024)"),
        (0, "a number (0)"),
        (b"Databases", "a byte string"),
        (bytearray(b"Databases"), "a byte string"),
        (datetime.date(2026, 9, 29), "a date (2026-09-29)"),
        (datetime.datetime(2026, 9, 29, 10, 0), "a date and time (2026-09-29 10:00:00)"),
        (decimal.Decimal("20.24"), "a value of type Decimal"),
    ]

    def test_non_string_values_of_str_options_fail(self):
        for option in self.STR_OPTIONS:
            for value, kind in self.VALUES:
                with self.subTest(option=option, value=value):
                    self.assertEqual(argument_error(self, {option: value}), type_message(option, kind))

    def test_yaml_values_that_would_change_silently_fail(self):
        """The message shows the value as YAML read it, so the author can see that the text changed."""
        cases = [
            ("folder_name: 1.10", "a number (1.1)"),
            ("folder_name: yes", "a boolean (True)"),
            ("folder_name: 007", "a number (7)"),
            ("folder_name: 010", "a number (8)"),
            ("folder_name: 1_000", "a number (1000)"),
            ("folder_name: 0x1F", "a number (31)"),
            ("folder_name: +12", "a number (12)"),
            ("folder_name: 2026-09-29", "a date (2026-09-29)"),
            ("folder_name: 2026-9-29 10:00:00", "a date and time (2026-09-29 10:00:00)"),
            ("folder_name: [Databases, Web]", "a list"),
            ("folder_name: {name: Databases}", "a dictionary"),
        ]
        for text, kind in cases:
            with self.subTest(yaml=text):
                self.assertEqual(argument_error(self, yaml.safe_load(text)), type_message("folder_name", kind))

    def test_an_int_fails_and_a_quoted_number_is_a_string(self):
        for option in self.STR_OPTIONS:
            with self.subTest(option=option):
                self.assertEqual(argument_error(self, {option: 2024}), type_message(option, "a number (2024)"))
                self.assertEqual(validate({option: "2024"})[option], "2024")
                self.assertEqual(validate({option: "007"})[option], "007")
                self.assertEqual(validate(yaml.safe_load("{}: '007'".format(option)))[option], "007")

    def test_null_and_type_errors_are_reported_together_in_sorted_order(self):
        """Each pre-check message ends with a period, so a space separates them."""
        message = argument_error(self, {"subfolder_uid": True, "shared_folder_uid": None, "folder_name": 7})
        self.assertEqual(message, " ".join([
            type_message("folder_name", "a number (7)"),
            null_message("shared_folder_uid"),
            type_message("subfolder_uid", "a boolean (True)"),
        ]))

    def test_a_type_error_is_reported_without_the_validator_messages(self):
        self.assertEqual(argument_error(self, {"folder_name": True, "folder_nmae": "x"}),
                         type_message("folder_name", "a boolean (True)"))
        self.assertEqual(argument_error(self, {"folder_name": 2024, "folder_path": "Databases"}),
                         type_message("folder_name", "a number (2024)"))

    def test_the_type_check_is_only_for_str_options(self):
        """folder_path is raw, so get_folder checks it. include_subfolders is bool, so the validator checks it."""
        self.assertIs(validate({"folder_path": True})["folder_path"], True)
        self.assertEqual(validate({"folder_path": ["Databases", 2024]})["folder_path"], ["Databases", 2024])
        message = argument_error(self, {"include_subfolders": ["a"]})
        self.assertTrue(message.startswith("argument 'include_subfolders' is of type "), message)
        self.assertNotIn("must be a string", message)


class VaultStrings:
    """
    Real vault-encrypted strings of the installed ansible-core, made with a test-only password: EncryptedString on
    ansible-core 2.19 and later, and AnsibleVaultEncryptedUnicode before. The ansible modules are imported when a
    test runs, not when this file is loaded, because a playbook test can unload them and load new classes.
    """

    PASSWORD = b"keeper-get-folder-test-only"

    def __init__(self):
        from ansible.parsing.vault import VaultLib, VaultSecret

        self._secret = VaultSecret(self.PASSWORD)
        self._vault = VaultLib([("default", self._secret)])
        self._patch = None
        try:
            from ansible.parsing.vault import EncryptedString, VaultSecretsContext
        except ImportError:
            from ansible.parsing.yaml.objects import AnsibleVaultEncryptedUnicode
            self._class = AnsibleVaultEncryptedUnicode
        else:
            # EncryptedString gets the secrets from VaultSecretsContext when it decrypts.
            self._class = EncryptedString
            self._patch = patch.object(VaultSecretsContext, "_current",
                                       VaultSecretsContext([("default", self._secret)]))
            self._patch.start()

    def make(self, text):
        ciphertext = self._vault.encrypt(text, self._secret)
        if self._patch is not None:
            return self._class(ciphertext=ciphertext.decode())
        value = self._class(ciphertext)
        value.vault = self._vault
        return value

    def close(self):
        if self._patch is not None:
            self._patch.stop()


class KeeperGetFolderVaultTest(GetFolderTestCase):
    """
    A value that Ansible Vault encrypts in the playbook (!vault) is not a str, but it is a string value, so it must
    pass the option checks and work as a UID, a name, or a path. These tests use real vault-encrypted strings.
    """

    def setUp(self):
        self.vault = VaultStrings()
        self.addCleanup(self.vault.close)

    def test_the_test_values_are_real_vault_strings(self):
        value = self.vault.make("Databases")
        self.assertNotIsInstance(value, str)
        self.assertIsInstance(value, KeeperAnsible._vault_string_types())
        self.assertEqual(str(value), "Databases")

    def test_vault_shared_folder_uid_and_folder_name_pass_the_option_checks(self):
        """The validator turns each vault value into the decrypted str, and the lookup uses it."""
        args = validate({"shared_folder_uid": self.vault.make("SF_INFRA"), "folder_name": self.vault.make("Databases")})
        self.assertIsInstance(args["shared_folder_uid"], str)
        self.assertIsInstance(args["folder_name"], str)
        self.assertEqual((args["shared_folder_uid"], args["folder_name"]), ("SF_INFRA", "Databases"))
        self.assertEqual(self.uid_of(**args), "DB")

    def test_a_vault_subfolder_uid_passes_the_option_checks(self):
        args = validate({"subfolder_uid": self.vault.make("PROD"), "folder_name": "EU"})
        self.assertEqual(self.uid_of(**args), "EU")

    def test_a_vault_string_folder_path_is_split_on_slash(self):
        value = self.vault.make("Databases/Production/EU")
        args = validate({"shared_folder_uid": "SF_INFRA", "folder_path": value})
        # folder_path is raw, so the validator keeps the vault value (as a copy), and get_folder reads it.
        self.assertIsInstance(args["folder_path"], KeeperAnsible._vault_string_types())
        self.assertEqual(str(args["folder_path"]), "Databases/Production/EU")
        self.assertEqual(self.uid_of(**args), "EU")
        self.assertEqual(self.uid_of(folder_path=self.vault.make("Infrastructure/Web/Databases")), "WEB_DB")

    def test_a_vault_item_in_a_list_folder_path_is_one_name(self):
        """A list item is one name, so a vault item can hold a "/"."""
        self.assertEqual(
            self.uid_of(shared_folder_uid="SF_INFRA", folder_path=["Databases", self.vault.make("Production")]),
            "PROD")
        self.assertEqual(self.uid_of(shared_folder_uid="SF_INFRA", folder_path=[self.vault.make("Prod/EU")]), "SLASH")
        self.assertEqual(self.uid_of(folder_path=(self.vault.make("Infrastructure"), self.vault.make("2024"))), "YEAR")

    def test_a_vault_item_next_to_an_empty_name_gives_the_empty_name_error(self):
        """
        The empty-name message shows the names as JSON, so each item must be turned into the decrypted str. A vault
        object in the list would make json.dumps fail with a TypeError instead.
        """
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_path=[self.vault.make("Databases"), ""]),
            empty_name('["Databases", ""]'))
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_path=["Databases", self.vault.make("")]),
            empty_name('["Databases", ""]'))

    def test_a_vault_value_with_a_trailing_newline_is_still_caught(self):
        """
        echo "UID" | ansible-vault encrypt_string also encrypts the newline. The whitespace check and the quoted
        name in the message show it, the same as for a plain string.
        """
        args = validate({"shared_folder_uid": self.vault.make("SF_INFRA\n"), "folder_name": "Databases"})
        self.assertEqual(self.lookup_error(**args),
                         "The shared_folder_uid 'SF_INFRA\\n' has leading or trailing whitespace.")
        args = validate({"shared_folder_uid": "SF_INFRA", "folder_name": self.vault.make("Databases\n")})
        self.assertEqual(self.lookup_error(**args),
                         'No folder named "Databases\\n" was found in the folder "Infrastructure" (UID SF_INFRA).')
        self.assertEqual(
            self.lookup_error(shared_folder_uid="SF_INFRA", folder_path=self.vault.make("Databases/Production\n")),
            'No folder named "Production\\n" was found in the folder "Infrastructure/Databases" (UID DB).')

    def test_a_blank_vault_value_is_blank(self):
        args = validate({"shared_folder_uid": self.vault.make(""), "folder_name": "Databases"})
        self.assertEqual(self.lookup_error(**args),
                         "The shared_folder_uid is set but blank. Set it to a folder UID, or remove it.")
        self.assertEqual(self.lookup_error(shared_folder_uid="SF_INFRA", folder_path=self.vault.make("")),
                         empty_name('[""]'))


class KeeperGetFolderActionPluginTest(unittest.TestCase):
    """ActionModule.run() with a fake client: the wiring between the task arguments and get_folder()."""

    GROUP = "group/keepersecurity.keeper_secrets_manager.keeper_secrets_manager"

    def make_action(self, args, check_mode=False, module_defaults=None):
        task = MagicMock()
        task.args = dict(args)
        task.async_val = 0
        task.check_mode = check_mode
        task.action = "keeper_get_folder"
        task.module_defaults = [] if module_defaults is None else module_defaults
        connection = MagicMock()
        connection._shell.tmpdir = None
        return action_plugin().ActionModule(task, connection, MagicMock(), MagicMock(), MagicMock(), MagicMock())

    def run_action(self, args, folders=None, check_mode=False, module_defaults=None):
        client = MagicMock()
        client.get_folders.return_value = standard_folders() if folders is None else folders
        created = []

        def fake_init(keeper, *init_args, **init_kwargs):
            created.append(init_kwargs)
            keeper.client = client

        with patch.object(KeeperAnsible, "__init__", fake_init):
            result = self.make_action(args, check_mode, module_defaults).run(task_vars={})
        return result, client, created

    def run_without_connection(self, args, module_defaults=None):
        """Run the task with a KeeperAnsible that must not be created, because the options are not valid."""
        def must_not_connect(keeper, *init_args, **init_kwargs):
            raise AssertionError("KeeperAnsible was created, but the task options are not valid")

        with patch.object(KeeperAnsible, "__init__", must_not_connect):
            return self.make_action(args, module_defaults=module_defaults).run(task_vars={})

    @staticmethod
    def failure(msg):
        return {"failed": True, "changed": False, "msg": msg}

    def assert_unsupported_failure(self, result, unknown):
        self.assertEqual(set(result), {"failed", "changed", "msg"})
        self.assertIs(result["failed"], True)
        self.assertIs(result["changed"], False)
        self.assertEqual(unsupported_names(result["msg"]), (set(unknown), SUPPORTED_OPTION_NAMES), result["msg"])

    def test_run_returns_the_folder_and_changed_false(self):
        result, client, created = self.run_action({"shared_folder_uid": "SF_INFRA", "folder_name": "Databases"})
        self.assertEqual(result, {
            "changed": False,
            "folder_uid": "DB",
            "folder_name": "Databases",
            "parent_uid": "SF_INFRA",
            "shared_folder_uid": "SF_INFRA",
        })
        self.assertEqual(len(created), 1)

    def test_run_passes_each_option_to_get_folder(self):
        """Each option must reach its own parameter; a swap of the two UIDs would start the lookup elsewhere."""
        with patch.object(KeeperAnsible, "get_folder", return_value={"folder_uid": "X"}) as get_folder:
            self.run_action({"shared_folder_uid": "SF_INFRA", "subfolder_uid": "PROD",
                             "folder_path": ["EU", "2024"], "include_subfolders": "yes"})
        get_folder.assert_called_once_with(shared_folder_uid="SF_INFRA", subfolder_uid="PROD", folder_name=None,
                                           folder_path=["EU", "2024"], include_subfolders=True)
        with patch.object(KeeperAnsible, "get_folder", return_value={"folder_uid": "X"}) as get_folder:
            self.run_action({"folder_name": "2024"})
        get_folder.assert_called_once_with(shared_folder_uid=None, subfolder_uid=None, folder_name="2024",
                                           folder_path=None, include_subfolders=False)

    def test_run_returns_subfolders_only_when_asked(self):
        result, _client, _created = self.run_action({"subfolder_uid": "EU", "include_subfolders": "yes"})
        self.assertEqual(result["subfolders"], [item("FRA", "Frankfurt", "EU")])
        result, _client, _created = self.run_action({"subfolder_uid": "EU", "include_subfolders": "no"})
        self.assertNotIn("subfolders", result)

    def test_run_returns_option_errors_as_a_failure_before_it_connects(self):
        """
        An option error is a returned failure, so failed_when, ignore_errors, and rescue work on it. The message
        has no prefix, and KeeperAnsible is not created, so no connection and no request is made.
        """
        cases = [
            ({"folder_name": "Databases", "folder_path": "Databases"},
             "parameters are mutually exclusive: folder_name|folder_path"),
            ({"shared_folder_uid": None, "folder_name": "Infrastructure"}, null_message("shared_folder_uid")),
            ({"shared_folder_uid": "SF_INFRA", "folder_name": True}, type_message("folder_name", "a boolean (True)")),
            ({"subfolder_uid": ["PROD", "EU"]}, type_message("subfolder_uid", "a list")),
            ({"shared_folder_uid": "SF_INFRA", "folder_name": 2024}, type_message("folder_name", "a number (2024)")),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(self.run_without_connection(args), self.failure(expected))
        self.assert_unsupported_failure(
            self.run_without_connection({"shared_folder_uid": "SF_INFRA", "folder_nmae": "Databases"}),
            ["folder_nmae"])
        result = self.run_without_connection({"shared_folder_uid": "SF_INFRA", "include_subfolders": "maybe"})
        self.assertEqual(set(result), {"failed", "changed", "msg"})
        self.assertEqual((result["failed"], result["changed"]), (True, False))
        self.assertIn("The value 'maybe' is not a valid boolean.", result["msg"])

    def test_run_null_option_does_not_mean_not_set(self):
        """
        Before the null check, both tasks succeeded: the first one found the top-level "Infrastructure", and the
        second one returned the shared folder itself instead of a subfolder.
        """
        self.assertEqual(self.run_without_connection({"shared_folder_uid": None, "folder_name": "Infrastructure"}),
                         self.failure(null_message("shared_folder_uid")))
        self.assertEqual(self.run_without_connection({"shared_folder_uid": "SF_INFRA", "folder_name": None}),
                         self.failure(null_message("folder_name")))
        for option in ("subfolder_uid", "folder_path", "include_subfolders"):
            with self.subTest(option=option):
                self.assertEqual(self.run_without_connection({"shared_folder_uid": "SF_INFRA", option: None}),
                                 self.failure(null_message(option)))

    def test_run_returns_a_lookup_error_as_a_failure(self):
        result, _client, created = self.run_action({"shared_folder_uid": "SF_INFRA", "folder_name": "Nope"})
        self.assertEqual(result, self.failure("Could not look up folder: " + not_found_in("Nope", "Infrastructure",
                                                                                          "SF_INFRA")))
        self.assertEqual(len(created), 1)

    def test_run_returns_any_exception_as_a_failure(self):
        with patch.object(KeeperAnsible, "get_folder", side_effect=RuntimeError("unexpected")):
            result, _client, _created = self.run_action({"shared_folder_uid": "SF_INFRA"})
        self.assertEqual(result, self.failure("Could not look up folder: unexpected"))

    def test_run_returns_blank_and_path_errors_as_a_failure(self):
        cases = [
            ({"shared_folder_uid": "   "},
             "The shared_folder_uid is set but blank. Set it to a folder UID, or remove it."),
            ({"folder_path": "Infrastructure//Databases"}, empty_name('["Infrastructure", "", "Databases"]')),
            ({"shared_folder_uid": "SF_INFRA", "folder_path": ["Databases", True]},
             path_item_message("a boolean (True)")),
            ({"folder_path": ["Infrastructure", 2024]}, path_item_message("a number (2024)")),
            ({"shared_folder_uid": "SF_INFRA", "folder_name": "Databases\n"},
             'No folder named "Databases\\n" was found in the folder "Infrastructure" (UID SF_INFRA).'),
            ({}, NOTHING_TO_LOOK_UP),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                result, _client, _created = self.run_action(args)
                self.assertEqual(result, self.failure("Could not look up folder: " + expected))

    def test_run_accepts_vault_values(self):
        """Vault-encrypted option values pass the option checks, and the lookup uses the decrypted text."""
        vault = VaultStrings()
        self.addCleanup(vault.close)
        result, _client, created = self.run_action({
            "shared_folder_uid": vault.make("SF_INFRA"),
            "folder_path": [vault.make("Databases"), "Production"],
        })
        self.assertEqual(result, {
            "changed": False,
            "folder_uid": "PROD",
            "folder_name": "Production",
            "parent_uid": "DB",
            "shared_folder_uid": "SF_INFRA",
        })
        self.assertEqual(len(created), 1)
        result, _client, _created = self.run_action({"subfolder_uid": vault.make("DB"),
                                                     "folder_name": vault.make("Staging")})
        self.assertEqual(result["folder_uid"], "STG")

    def test_run_still_raises_a_connection_error(self):
        """KeeperAnsible is created outside the try, so a config error is raised, not returned."""
        class ConfigProblem(Exception):
            pass

        def broken_init(keeper, *init_args, **init_kwargs):
            raise ConfigProblem("There is no config file and the Ansible variable contain no config keys.")

        with patch.object(KeeperAnsible, "__init__", broken_init):
            with self.assertRaises(ConfigProblem):
                self.make_action({"shared_folder_uid": "SF_INFRA"}).run(task_vars={})

    def test_run_in_check_mode_gives_the_same_result(self):
        """The module changes nothing, so check mode runs the real lookup, and it is not skipped."""
        args = {"folder_path": "Infrastructure/Databases", "include_subfolders": True}
        normal, _client, _created = self.run_action(args)
        checked, client, _created = self.run_action(args, check_mode=True)
        self.assertEqual(checked, normal)
        self.assertIs(checked["changed"], False)
        self.assertEqual({name for name, _a, _k in client.method_calls}, {"get_folders"})
        failed, _client, _created = self.run_action({"shared_folder_uid": "SF_INFRA", "folder_name": "Nope"},
                                                    check_mode=True)
        self.assertEqual(failed, self.failure("Could not look up folder: " + not_found_in(
            "Nope", "Infrastructure", "SF_INFRA")))

    def test_group_default_option_that_the_module_does_not_have_is_ignored(self):
        """
        Ansible gives the defaults of an action group to every module in the group, so keeper_get_folder gets the
        cache option of keeper_get. The plugin must drop it instead of failing on it.
        """
        defaults = [{self.GROUP: {"cache": "{{ records }}"}}]
        result, _client, created = self.run_action(
            {"shared_folder_uid": "SF_INFRA", "folder_name": "Databases", "cache": "the rendered records"},
            module_defaults=defaults)
        self.assertEqual(result["folder_uid"], "DB")
        self.assertNotIn("failed", result)
        self.assertEqual(len(created), 1)

    def test_the_same_unknown_option_only_in_the_task_still_fails(self):
        args = {"shared_folder_uid": "SF_INFRA", "cache": "the rendered records"}
        for defaults in ([], [{self.GROUP: {"other_option": 1}}], [{"keeper_get_folder": {"cache": "x"}}],
                         [{"keepersecurity.keeper_secrets_manager.keeper_get_folder": {"cache": "x"}}]):
            with self.subTest(module_defaults=defaults):
                self.assert_unsupported_failure(self.run_without_connection(args, module_defaults=defaults),
                                                ["cache"])

    def test_a_misspelled_option_still_fails_next_to_a_group_default(self):
        result = self.run_without_connection(
            {"shared_folder_uid": "SF_INFRA", "cache": "x", "folder_nmae": "Databases"},
            module_defaults=[{self.GROUP: {"cache": "x"}}])
        self.assert_unsupported_failure(result, ["folder_nmae"])

    def test_a_group_default_for_an_option_that_the_module_has_is_still_checked(self):
        """The ignore list never removes an option of the module, so a group default for it is validated."""
        defaults = [{self.GROUP: {"include_subfolders": "yes", "folder_name": None}}]
        self.assertEqual(
            self.run_without_connection({"shared_folder_uid": "SF_INFRA", "folder_name": None},
                                        module_defaults=defaults),
            self.failure(null_message("folder_name")))
        result, _client, _created = self.run_action({"subfolder_uid": "EU", "include_subfolders": "yes"},
                                                    module_defaults=defaults)
        self.assertEqual(result["subfolders"], [item("FRA", "Frankfurt", "EU")])

    def test_a_group_default_of_another_collection_does_not_hide_a_wrong_option(self):
        """
        Ansible gives a group default only to the modules in that group, so the group of another collection never
        reaches keeper_get_folder. Its option names must not hide a mistake. Here keeper_get_folder has no
        folder_uid option: if it were dropped, the lookup would find a different folder, at the top level.
        """
        args = {"folder_uid": "SF_INFRA", "folder_name": "Databases"}
        for defaults in ([{"group/amazon.aws.aws": {"folder_uid": "x"}}],
                         [{"group/ansible.builtin.keeper_secrets_manager": {"folder_uid": "x"}}]):
            with self.subTest(module_defaults=defaults):
                self.assert_unsupported_failure(self.run_without_connection(args, module_defaults=defaults),
                                                ["folder_uid"])


class KeeperGetFolderDocumentationTest(unittest.TestCase):
    """The documentation must match the code, because ansible-doc and Galaxy show it to users."""

    def test_docs_stub_matches_the_action_plugin(self):
        for name in ("DOCUMENTATION", "EXAMPLES", "RETURN"):
            with self.subTest(name=name):
                self.assertEqual(getattr(module_docs, name), getattr(action_plugin(), name))

    def test_documented_options_match_the_argument_spec(self):
        options = yaml.safe_load(action_plugin().DOCUMENTATION)["options"]
        self.assertEqual(set(options), set(action_plugin().ActionModule.ARGUMENT_SPEC))
        for name, spec in action_plugin().ActionModule.ARGUMENT_SPEC.items():
            with self.subTest(option=name):
                self.assertEqual(options[name]["type"], spec["type"])
                self.assertEqual(options[name].get("default"), spec.get("default"))
                self.assertFalse(options[name].get("required", False))

    def test_description_says_that_the_options_are_checked(self):
        description = " ".join(yaml.safe_load(action_plugin().DOCUMENTATION)["description"])
        for word in ("misspelled", "null", "wrong type"):
            with self.subTest(word=word):
                self.assertIn(word, description)

    def test_examples_use_only_valid_options(self):
        tasks = yaml.safe_load(action_plugin().EXAMPLES)
        lookups = [task["keeper_get_folder"] for task in tasks if "keeper_get_folder" in task]
        self.assertGreaterEqual(len(lookups), 4)
        for args in lookups:
            with self.subTest(args=args):
                validate(args)

    def test_return_documents_every_result_key(self):
        documented = yaml.safe_load(action_plugin().RETURN)
        self.assertEqual(set(documented),
                         {"folder_uid", "folder_name", "parent_uid", "shared_folder_uid", "subfolders"})

    def test_description_names_the_group_default_exception(self):
        description = " ".join(yaml.safe_load(action_plugin().DOCUMENTATION)["description"])
        self.assertIn("There is one exception. An option that a module_defaults entry for an action group of this "
                      "collection sets, and that this module does not have, is ignored.", description)

    def test_return_says_that_shared_folder_uid_can_be_null(self):
        documented = " ".join(yaml.safe_load(action_plugin().RETURN)["shared_folder_uid"]["description"])
        self.assertIn("Null", documented)
        self.assertIn("cycle", documented)

    def test_return_subfolders_sample_is_a_list_of_entries(self):
        sample = yaml.safe_load(action_plugin().RETURN)["subfolders"]["sample"]
        self.assertIsInstance(sample, list)
        self.assertGreaterEqual(len(sample), 1)
        for entry in sample:
            self.assertEqual(set(entry), {"folder_uid", "folder_name", "parent_uid"})


if __name__ == "__main__":
    unittest.main()
