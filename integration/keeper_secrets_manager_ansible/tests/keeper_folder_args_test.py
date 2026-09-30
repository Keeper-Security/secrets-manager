import ast
import datetime
import inspect
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import keeper_secrets_manager_ansible
from keeper_secrets_manager_ansible import KeeperAnsible, KeeperArgumentError

SPEC = dict(
    folder_uid=dict(type="str", required=True),
    folder_name=dict(type="str"),
    folder_path=dict(type="raw"),
    force=dict(type="bool", default=False),
)

GROUP = "group/keepersecurity.keeper_secrets_manager.keeper_secrets_manager"


def validate(args, **kwargs):
    return KeeperAnsible.validate_task_args("keeper_test_module", args, SPEC, **kwargs)


def split_supported(message):
    # ansible-core 2.12 lists the supported parameters in set order, and newer versions sort them. Compare the text
    # before the list exactly, and the list as a set.
    head, _, names = message.partition(" Supported parameters include: ")
    return head, set(names.rstrip(".").split(", "))


class ValidateTaskArgsTest(unittest.TestCase):
    """
    The option check that the folder modules run before they connect. A misspelled, null, or wrongly typed option
    must fail the task, because for these modules a silently ignored or converted option can change which folder a
    task renames or deletes.
    """

    def test_valid_arguments_get_defaults_and_types(self):
        self.assertEqual(
            validate({"folder_uid": "UID", "force": "yes"}),
            {"folder_uid": "UID", "folder_name": None, "folder_path": None, "force": True})

    def test_the_input_is_not_changed(self):
        args = {"folder_uid": "UID", "extra": "x"}
        with self.assertRaises(KeeperArgumentError):
            validate(args)
        validate(args, ignore=["extra"])
        self.assertEqual(args, {"folder_uid": "UID", "extra": "x"})

    def test_error_is_a_plain_exception_not_an_ansible_error(self):
        # The action plugins return the message as a task failure. A plain exception class also stays the same
        # class when the test framework reloads the ansible modules between playbook runs.
        self.assertTrue(issubclass(KeeperArgumentError, ValueError))
        self.assertFalse(any(c.__module__.startswith("ansible") for c in KeeperArgumentError.__mro__))

    def test_unknown_option_fails(self):
        with self.assertRaises(KeeperArgumentError) as ctx:
            validate({"folder_uid": "UID", "forse": True})
        self.assertEqual(
            split_supported(str(ctx.exception)),
            ("Unsupported parameters for (keeper_test_module) module: forse.",
             {"folder_name", "folder_path", "folder_uid", "force"}))

    def test_an_option_name_that_is_not_a_string_fails(self):
        # YAML reads an unquoted key such as 1 as a number. Before this check, sorting the names raised TypeError.
        with self.assertRaises(KeeperArgumentError) as ctx:
            validate({"folder_uid": "UID", 1: "x", 2.5: "y"})
        self.assertEqual(
            str(ctx.exception),
            "Unsupported parameters for (keeper_test_module) module: 1, 2.5. An option name must be a string.")

    def test_validator_errors_are_joined_with_a_semicolon(self):
        with self.assertRaises(KeeperArgumentError) as ctx:
            validate({"forse": True})
        self.assertEqual(
            split_supported(str(ctx.exception)),
            ("missing required arguments: folder_uid; Unsupported parameters for (keeper_test_module) module: forse.",
             {"folder_name", "folder_path", "folder_uid", "force"}))

    def test_mutually_exclusive_options_fail(self):
        with self.assertRaises(KeeperArgumentError) as ctx:
            validate({"folder_uid": "UID", "folder_name": "a", "folder_path": "b"},
                     mutually_exclusive=[["folder_name", "folder_path"]])
        self.assertEqual(str(ctx.exception), "parameters are mutually exclusive: folder_name|folder_path")

    def test_a_bad_boolean_fails(self):
        with self.assertRaises(KeeperArgumentError) as ctx:
            validate({"folder_uid": "UID", "force": "maybe"})
        self.assertIn("argument 'force' is of type", str(ctx.exception))

    def test_null_option_fails(self):
        for option in ["folder_uid", "folder_name", "folder_path", "force"]:
            with self.subTest(option=option):
                args = {"folder_uid": "UID"}
                args[option] = None
                with self.assertRaises(KeeperArgumentError) as ctx:
                    validate(args)
                self.assertEqual(
                    str(ctx.exception),
                    "The {} option is null. Give it a value, or leave the option out of the task.".format(option))

    def test_every_null_option_is_named_in_sorted_order(self):
        with self.assertRaises(KeeperArgumentError) as ctx:
            validate({"folder_uid": "UID", "folder_path": None, "folder_name": None})
        self.assertEqual(
            str(ctx.exception),
            "The folder_name option is null. Give it a value, or leave the option out of the task. "
            "The folder_path option is null. Give it a value, or leave the option out of the task.")

    def test_a_null_unknown_option_is_reported_as_unsupported(self):
        with self.assertRaises(KeeperArgumentError) as ctx:
            validate({"folder_uid": "UID", "folder_nmae": None})
        self.assertIn("Unsupported parameters for (keeper_test_module) module: folder_nmae.", str(ctx.exception))

    def test_a_null_check_failure_hides_the_validator_errors(self):
        # Only the pre-check messages are raised, so a null is never masked by, or mixed with, a later error.
        with self.assertRaises(KeeperArgumentError) as ctx:
            validate({"folder_uid": None, "forse": True})
        self.assertEqual(
            str(ctx.exception),
            "The folder_uid option is null. Give it a value, or leave the option out of the task.")

    def test_a_str_option_must_be_a_string(self):
        cases = [
            (["a", "b"], "a list"),
            (("a",), "a list"),
            ({"name": "a"}, "a dictionary"),
            (True, "a boolean (True)"),
            (False, "a boolean (False)"),
            (1.1, "a number (1.1)"),
            (7, "a number (7)"),
            (0, "a number (0)"),
            (datetime.date(2026, 9, 29), "a date (2026-09-29)"),
            (datetime.datetime(2026, 9, 29, 10, 0), "a date and time (2026-09-29 10:00:00)"),
            ({"a"}, "a list"),
            (b"UID", "a byte string"),
            (object(), "a value of type object"),
        ]
        for value, kind in cases:
            with self.subTest(value=value):
                with self.assertRaises(KeeperArgumentError) as ctx:
                    validate({"folder_uid": value})
                self.assertEqual(
                    str(ctx.exception),
                    "The folder_uid option must be a string, but it is {}. Put quotes around the value, or use the "
                    "string filter.".format(kind))

    def test_an_integer_is_not_a_string(self):
        # YAML changes the text of some numbers that have no quotes: 007 becomes 7, and 010 becomes 8. The text
        # that the playbook author wrote cannot be recovered from the number, so a number is not accepted.
        with self.assertRaises(KeeperArgumentError):
            validate({"folder_uid": 7})
        self.assertEqual(validate({"folder_uid": "007"})["folder_uid"], "007")

    def test_a_vault_encrypted_string_is_a_string(self):
        # A value that Ansible Vault encrypts in the playbook is not a str before ansible-core 2.19, and not a str
        # subclass after it. str() gives the decrypted text.
        class FakeVaultString(object):
            def __str__(self):
                return "DECRYPTED_UID"

        with patch.object(KeeperAnsible, "_vault_string_types", return_value=(FakeVaultString,)):
            self.assertEqual(validate({"folder_uid": FakeVaultString()})["folder_uid"], "DECRYPTED_UID")
        with self.assertRaises(KeeperArgumentError):
            validate({"folder_uid": FakeVaultString()})

    def test_the_vault_class_of_this_ansible_core_is_found(self):
        types = KeeperAnsible._vault_string_types()
        self.assertEqual(len(types), 1)
        self.assertIn(types[0].__name__, ("EncryptedString", "AnsibleVaultEncryptedUnicode"))

    def test_a_str_subclass_is_a_valid_str_value(self):
        # Ansible gives a playbook string as a subclass of str (AnsibleUnicode, or a tagged str in newer versions).
        class TaggedStr(str):
            pass
        self.assertEqual(validate({"folder_uid": TaggedStr("UID")})["folder_uid"], "UID")

    def test_the_type_check_is_only_for_str_options(self):
        self.assertEqual(validate({"folder_uid": "UID", "folder_path": ["a", 1]})["folder_path"], ["a", 1])

    def test_ignored_names_are_removed_only_if_the_module_does_not_have_them(self):
        args = {"folder_uid": "UID", "cache": "x", "shared_folder_uid": "S"}
        self.assertEqual(
            validate(args, ignore=["cache", "shared_folder_uid"]),
            {"folder_uid": "UID", "folder_name": None, "folder_path": None, "force": False})

    def test_an_ignored_name_that_the_module_has_is_still_checked(self):
        with self.assertRaises(KeeperArgumentError) as ctx:
            validate({"folder_uid": "UID", "force": "maybe"}, ignore=["force"])
        self.assertIn("argument 'force' is of type", str(ctx.exception))
        with self.assertRaises(KeeperArgumentError):
            validate({"folder_uid": None}, ignore=["folder_uid"])

    def test_an_ignored_name_also_matches_a_name_that_is_not_a_string(self):
        # group_default_options gives the names as text. A group default with the key 1 (YAML reads an unquoted 1
        # as a number) is ignored like any other name that the module does not have.
        self.assertEqual(validate({"folder_uid": "UID", 1: "x"}, ignore=["1"])["folder_uid"], "UID")
        with self.assertRaises(KeeperArgumentError):
            validate({"folder_uid": "UID", 1: "x"}, ignore=["2"])

    def test_an_unknown_option_that_is_not_ignored_still_fails(self):
        with self.assertRaises(KeeperArgumentError) as ctx:
            validate({"folder_uid": "UID", "cache": "x", "forse": True}, ignore=["cache"])
        self.assertIn("module: forse.", str(ctx.exception))
        self.assertNotIn("cache", str(ctx.exception).split("Supported parameters include")[0])


class GroupDefaultOptionsTest(unittest.TestCase):
    """
    Ansible gives the module_defaults of an action group to every module in the group. The option names of a group
    entry are ignored by the strict folder modules when they do not have them.
    """

    def test_no_module_defaults(self):
        self.assertEqual(KeeperAnsible.group_default_options(SimpleNamespace(module_defaults=None)), set())
        self.assertEqual(KeeperAnsible.group_default_options(SimpleNamespace(module_defaults=[])), set())
        self.assertEqual(KeeperAnsible.group_default_options(SimpleNamespace()), set())

    def test_group_entries_give_their_option_names(self):
        task = SimpleNamespace(module_defaults=[
            {GROUP: {"shared_folder_uid": "S", "cache": "C"}},
            {"group/keepersecurity.keeper_secrets_manager.other_group": {"uid": "U"}},
        ])
        self.assertEqual(KeeperAnsible.group_default_options(task), {"shared_folder_uid", "cache", "uid"})

    def test_groups_of_other_collections_are_not_read(self):
        # Ansible gives a group default only to the modules in that group, so another collection's group never
        # reaches these modules. Its option names must not hide a misspelled option in a task.
        task = SimpleNamespace(module_defaults=[
            {"group/amazon.aws.aws": {"folder_uid": "X", "region": "us"}},
            {"group/ansible.builtin.keeper_secrets_manager": {"cache": "C"}},
        ])
        self.assertEqual(KeeperAnsible.group_default_options(task), set())

    def test_module_entries_are_not_group_defaults(self):
        # Defaults for one module by name are applied only to that module, so they always match its options.
        task = SimpleNamespace(module_defaults=[{"keepersecurity.keeper_secrets_manager.keeper_create": {"x": 1}}])
        self.assertEqual(KeeperAnsible.group_default_options(task), set())

    def test_a_single_dict_is_accepted(self):
        task = SimpleNamespace(module_defaults={GROUP: {"cache": "C"}})
        self.assertEqual(KeeperAnsible.group_default_options(task), {"cache"})

    def test_values_that_are_not_dicts_are_skipped(self):
        task = SimpleNamespace(module_defaults=["not a dict", {GROUP: ["cache"]}, {GROUP: None}])
        self.assertEqual(KeeperAnsible.group_default_options(task), set())

    def test_a_templated_group_value_is_resolved_with_the_templar(self):
        templar = MagicMock()
        templar.template.return_value = {"cache": "C"}
        task = SimpleNamespace(module_defaults=[{GROUP: "{{ keeper_defaults }}"}])
        self.assertEqual(KeeperAnsible.group_default_options(task, templar), {"cache"})
        templar.template.assert_called_once_with("{{ keeper_defaults }}")

    def test_a_templated_value_is_skipped_without_a_templar_or_on_a_template_error(self):
        task = SimpleNamespace(module_defaults=[{GROUP: "{{ keeper_defaults }}"}])
        self.assertEqual(KeeperAnsible.group_default_options(task), set())
        templar = MagicMock()
        templar.template.side_effect = ValueError("undefined variable")
        self.assertEqual(KeeperAnsible.group_default_options(task, templar), set())


class MessageHelperTest(unittest.TestCase):

    def test_describe_value(self):
        self.assertEqual(KeeperAnsible._describe_value(True), "a boolean (True)")
        self.assertEqual(KeeperAnsible._describe_value(7), "a number (7)")
        self.assertEqual(KeeperAnsible._describe_value(1.5), "a number (1.5)")
        self.assertEqual(KeeperAnsible._describe_value(datetime.date(2026, 9, 29)), "a date (2026-09-29)")
        self.assertEqual(KeeperAnsible._describe_value(datetime.datetime(2026, 9, 29, 10, 0, 0)),
                         "a date and time (2026-09-29 10:00:00)")
        self.assertEqual(KeeperAnsible._describe_value({}), "a dictionary")
        self.assertEqual(KeeperAnsible._describe_value([]), "a list")
        self.assertEqual(KeeperAnsible._describe_value(()), "a list")
        self.assertEqual(KeeperAnsible._describe_value(frozenset()), "a list")
        self.assertEqual(KeeperAnsible._describe_value(b"x"), "a byte string")
        self.assertEqual(KeeperAnsible._describe_value(None), "a value of type NoneType")

    def test_join_messages(self):
        self.assertEqual(KeeperAnsible._join_messages([]), "")
        self.assertEqual(KeeperAnsible._join_messages(["One."]), "One.")
        self.assertEqual(KeeperAnsible._join_messages(["One.", "Two."]), "One. Two.")
        self.assertEqual(KeeperAnsible._join_messages(["missing required arguments: a", "Two."]),
                         "missing required arguments: a; Two.")

    def test_quote_shows_hidden_characters(self):
        self.assertEqual(KeeperAnsible._quote("Databases"), '"Databases"')
        self.assertEqual(KeeperAnsible._quote("Databases\n"), '"Databases\\n"')
        self.assertEqual(KeeperAnsible._quote("a\tb"), '"a\\tb"')
        self.assertEqual(KeeperAnsible._quote('say "hi"'), '"say \\"hi\\""')
        self.assertEqual(KeeperAnsible._quote("Données"), '"Données"')


class LazyImportTest(unittest.TestCase):
    """
    ArgumentSpecValidator needs ansible-core 2.11. It must be imported only inside validate_task_args, so that
    every module that does not validate its options keeps working on an older Ansible.
    """

    def test_arg_spec_is_not_imported_when_the_module_loads(self):
        lazy = ("ansible.module_utils.common.arg_spec", "ansible.module_utils.errors")
        found = []

        def visit(node, in_function):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ImportFrom) and child.module in lazy:
                    found.append(child.module)
                    self.assertTrue(in_function, "{} is imported when the module loads".format(child.module))
                visit(child, in_function or isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)))

        visit(ast.parse(inspect.getsource(keeper_secrets_manager_ansible)), False)
        self.assertEqual(sorted(found), sorted(lazy), "the lazy imports were not found")
