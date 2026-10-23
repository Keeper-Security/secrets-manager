import sys


def pytest_collection_finish(session):
    """
    Unload the ansible modules after pytest collects the tests.

    A test module that imports a plugin when pytest collects it (keeper_redact_test.py, for example) starts
    ansible's plugin loader with the default paths. The first playbook test of the run then fails with "couldn't
    resolve module/action", because AnsibleTestFramework sets the Keeper plugin paths only when that test runs. After
    the unload, the first playbook test loads the ansible modules again, with the right paths, in any test order.
    AnsibleTestFramework unloads them the same way after each playbook run.
    """
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)
