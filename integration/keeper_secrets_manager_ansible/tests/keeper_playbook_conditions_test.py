import unittest
from pathlib import Path

import yaml

TESTS_DIR = Path(__file__).resolve().parent
PLAYBOOKS = (TESTS_DIR / "ansible_example/playbooks", TESTS_DIR / "integration/targets")

# Task keywords whose value is a condition, or a list of conditions.
CONDITION_KEYWORDS = ("when", "failed_when", "changed_when", "until")


class PlaybookLoader(yaml.SafeLoader):
    """A safe YAML loader that also reads tags that only Ansible knows, such as !vault, as plain values."""


def construct_ansible_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


PlaybookLoader.add_multi_constructor("!", construct_ansible_tag)


def tasks_of(items):
    """Every task in a list of plays or tasks, including the tasks in block, rescue, and always sections."""
    for item in items or []:
        if not isinstance(item, dict):
            continue
        for section in ("tasks", "pre_tasks", "post_tasks", "handlers", "block", "rescue", "always"):
            if section in item:
                for task in tasks_of(item[section]):
                    yield task
        if "hosts" not in item:
            yield item


class PlaybookConditionsTest(unittest.TestCase):
    """
    A condition must be a string, or a list of strings. If a condition has an unquoted ": ", YAML reads it as a
    dictionary. ansible-core 2.19 and later fail on that, but older versions treat a dictionary as true, so an assert
    in a test playbook passes without checking anything.
    """

    def test_every_condition_is_a_string(self):
        paths = sorted(path for directory in PLAYBOOKS for path in directory.rglob("*.yml"))
        self.assertGreater(len(paths), 0)
        self.assertTrue(any(PLAYBOOKS[1] in path.parents for path in paths), "integration targets were not discovered")
        problems = []
        for path in paths:
            with open(path) as fh:
                plays = yaml.load(fh, Loader=PlaybookLoader)
            for task in tasks_of(plays):
                name = task.get("name", "(no name)")
                conditions = []
                for keyword in CONDITION_KEYWORDS:
                    if keyword in task:
                        conditions.append((keyword, task[keyword]))
                for action in ("assert", "ansible.builtin.assert"):
                    if isinstance(task.get(action), dict) and "that" in task[action]:
                        conditions.append(("assert that", task[action]["that"]))
                for keyword, value in conditions:
                    for condition in value if isinstance(value, list) else [value]:
                        if not isinstance(condition, (str, bool)):
                            problems.append("{}: task {!r}: {} has a {} condition: {!r}".format(
                                path.relative_to(TESTS_DIR), name, keyword, type(condition).__name__, condition))
        self.assertEqual(problems, [])
