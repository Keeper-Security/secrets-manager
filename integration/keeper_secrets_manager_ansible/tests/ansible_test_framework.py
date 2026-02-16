from unittest.mock import patch
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
import keeper_secrets_manager_ansible.plugins
from importlib import import_module
import os
import sys
from io import StringIO
import subprocess
import re
import json


class AnsibleTestFramework:

    def __init__(self, playbook, **kwargs):

        self.base_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ansible_example")
        self.plugin_base_dir = os.path.join(os.path.dirname(keeper_secrets_manager_ansible.plugins.__file__))
        self.playbook = playbook
        self.connection = kwargs.get("connection", "local")
        self.extra_vars = kwargs.get("vars", [])
        if self.extra_vars is None:
            self.extra_vars = []

        self.mock_responses = kwargs.get("mock_responses", [])

    def ansible_config(self):

        return f"""[defaults]
inventory=./inventory
playbook_dir=./playbooks
action_plugins={self.plugin_base_dir}/action
lookup_plugins={self.plugin_base_dir}/lookup

[inventory]
enable_plugins=ini,host_list,script
"""

    def generate_ansible_config(self):

        with open(os.path.join(self.base_dir, "ansible.cfg"), "w") as fh:
            fh.write(self.ansible_config())
            fh.close()

    def run(self):

        orig_wor_dir = os.getcwd()
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        results = {}
        stdout_text = ""
        stderr_text = ""

        try:
            secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(config=mock.MockConfig.make_base64()))
            queue = mock.ResponseQueue(client=secrets_manager)
            for response in self.mock_responses:
                queue.add_response(response)

            # Set the custom post function so SDK uses mock responses
            secrets_manager.custom_post_function = queue.post_method

            with patch('keeper_secrets_manager_ansible.KeeperAnsible.get_client') as mock_client:
                mock_client.return_value = secrets_manager

                self.generate_ansible_config()

                sp = subprocess.run(["which", "ansible-playbook"], text=True, capture_output=True)
                ansible_playbook = sp.stdout

                args = [
                    ansible_playbook.strip(),
                    "-vvvvvv",
                    "-c",
                    "local",
                    "-i",
                    os.path.join(self.base_dir, "inventory", "all")
                ]

                if len(self.extra_vars) > 0:
                    for key in self.extra_vars:
                        args.append("--extra-vars")
                        if isinstance(self.extra_vars[key], str) is True:
                            args.append(f"{key}=\'{self.extra_vars[key]}\'")
                        else:
                            args.append(json.dumps({key: self.extra_vars[key]}))

                args.append(os.path.join(self.base_dir, "playbooks", self.playbook))

                print(f"Command - {' '.join(args)}")

                print(f"Ansible Directory - {self.base_dir}")
                print(f"Python Path - {os.environ.get('PYTHONPATH', 'Not set')}")
                print()

                os.chdir(self.base_dir)

                redirected_output = None
                redirected_error = None

                try:
                    from ansible import constants as C
                    C.ANSIBLE_HOME = self.base_dir
                    C.CONFIG_FILE = os.path.join(self.base_dir, "ansible.cfg")
                    C.DEFAULT_ACTION_PLUGIN_PATH = os.path.join(self.plugin_base_dir, "action")
                    C.DEFAULT_LOOKUP_PLUGIN_PATH = os.path.join(self.plugin_base_dir, "lookup")

                    # Are we running 3.8 or greater?
                    if sys.version_info[:2] >= (3, 8):
                        playbook = import_module("ansible.cli.playbook")
                    else:
                        print("USING Python 3.7/ANSIBLE 4.0 HACK")
                        # Python 3.7 will use Ansible 4, which CLI does not have a main() method. So we need
                        # to make a fake ansible-playbook which does.
                        playbook = import_module("tests.playbook_python_3_7")

                    redirected_output = StringIO()
                    redirected_error = StringIO()

                    sys.stdout = redirected_output
                    sys.stderr = redirected_error

                    # Set sys.argv instead of passing args (Ansible 2.20+ compatibility)
                    old_argv = sys.argv
                    sys.argv = args
                    playbook.main()
                    sys.argv = old_argv

                except SystemExit as err:
                    if int(str(err)) != 0:
                        raise Exception(f"Ansible exited with a non-zero: {err}")
                except ImportError as err:
                    raise Exception(f"Could not load the playbook CLI module: {err}")
                finally:
                    if redirected_output is not None:
                        stdout_text = redirected_output.getvalue()
                    if redirected_error is not None:
                        stderr_text = redirected_error.getvalue()
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr

                    print()
                    print("STDOUT")
                    print("-----------------------------------------------------------------------------------------")
                    print(stdout_text)

                    print()
                    print("STDERR")
                    print("-----------------------------------------------------------------------------------------")
                    print(stderr_text)

                    # Unload the ansible modules. They like to stuff things in classes and global places. If you
                    # don't, tests might interfere with each other.
                    for module in dict(sys.modules):
                        if module.startswith("ansible") is True:
                            print(f"unloading {module}")
                            sys.modules.pop(module, None)

                regex_str = "localhost\\s+:"
                statuses = ["ok", "changed", "unreachable", "failed", "skipped", "rescued", "ignored"]
                for status in statuses:
                    regex_str += f"\\s+{status}=(\\d+)"
                    results[status] = 0

                # Try stdout first, then stderr (Ansible 2.20+ outputs to stderr)
                match = re.search(regex_str, stdout_text, re.MULTILINE)
                if match is None:
                    match = re.search(regex_str, stderr_text, re.MULTILINE)

                if match is not None:
                    index = 1
                    for status in statuses:
                        results[status] = int(match.group(index))
                        index += 1

                print(results)

        except Exception as err:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            print(f"EXCEPTION CAUGHT: {err}")
            import traceback
            traceback.print_exc()
        finally:
            os.chdir(orig_wor_dir)
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        return results, stdout_text, stderr_text


