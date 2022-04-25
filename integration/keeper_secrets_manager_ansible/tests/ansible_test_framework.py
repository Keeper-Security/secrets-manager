from ansible import context
from ansible.cli import CLI
from ansible.module_utils.common.collections import ImmutableDict
from ansible.executor.playbook_executor import PlaybookExecutor
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager
from ansible.plugins.loader import add_all_plugin_dirs
from ansible.plugins.callback.default import CallbackModule
from ansible.utils.display import Display
from keeper_secrets_manager_core.dto.dtos import Record
from keeper_secrets_manager_core.crypto import CryptoUtils
import os
import sys
from io import StringIO
import base64
import json
import time
import uuid
import traceback


class AnsibleTestFramework:

    def __init__(self, base_dir, playbook, inventory, **kwargs):

        self.base_dir = base_dir
        self.playbook = playbook
        self.inventory = inventory
        self.connection = kwargs.get("connection", "local")
        self.extra_vars = kwargs.get("vars")
        self.plugin_base_dir = kwargs.get("plugin_base_dir")

    def run(self):

        orig_wor_dir = os.getcwd()
        os.chdir(self.base_dir)

        old_stdout = sys.stdout
        old_stderr = sys.stderr

        try:

            redirected_output = sys.stdout = StringIO()
            redirected_error = sys.stderr = StringIO()

            loader = DataLoader()

            # The ansible base directory.
            loader.set_basedir(self.base_dir)

            # This will scan the directory for all possible plugin directories and add them if it finds them. For
            # example if it finds a 'action_plugins' directory, it will added the directory to the action plugin
            # loader.
            add_all_plugin_dirs(self.plugin_base_dir)

            context.CLIARGS = ImmutableDict(
                tags={},
                listtags=False,
                listtasks=False,
                listhosts=False,
                syntax=False,
                connection=self.connection,
                module_path=None,
                forks=100,
                remote_user='xxx',
                private_key_file=None,
                ssh_common_args=None,
                ssh_extra_args=None,
                sftp_extra_args=None,
                scp_extra_args=None,
                become=False,
                become_method='sudo',
                become_user='root',
                verbosity=4,
                check=False,
                start_at_task=None
            )

            inventory = InventoryManager(
                loader=loader,
                sources=self.inventory
            )

            variable_manager = VariableManager(
                loader=loader,
                inventory=inventory,
                version_info=CLI.version_info(gitinfo=False)
            )

            # A hack to set the extra vars. Trying through the CLIARGS is a nightmare.
            if self.extra_vars is not None:
                state = variable_manager.__getstate__()
                for key in self.extra_vars:
                    state['extra_vars'][key] = self.extra_vars[key]

            playbook_exec = PlaybookExecutor(
                playbooks=[self.playbook],
                inventory=inventory,
                variable_manager=variable_manager,
                loader=loader,
                passwords={}
            )

            callback = CallbackModule()

            # Still not there. Trying to get display to show debug or v{1,5} messages
            callback._display.verbosity = 4
            callback.display_ok_hosts = True
            callback.display_skipped_hosts = False
            callback.show_per_host_start = False
            callback.display_failed_stderr = True
            playbook_exec._tqm._stdout_callback = callback

            playbook_exec.run()
            stats = playbook_exec._tqm._stats
            hosts = sorted(stats.processed.keys())
            results = [{h: stats.summarize(h)} for h in hosts]

        finally:
            os.chdir(orig_wor_dir)
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        out = redirected_output.getvalue()
        err = redirected_error.getvalue()

        return results, out, err


class RecordMaker:

    url_data = {}
    secret = b"11111111111111111111111111111111"

    @staticmethod
    def make_record(uid, title, record_type=None, fields=None, custom_fields=None):

        if record_type is None:
            record_type = "login"

        data = {
            "title": title,
            "type": record_type
        }
        if fields is not None:
            data["fields"] = []
            for field_type, value in fields.items():
                if type(value) is not list:
                    value = [value]
                data["fields"].append({
                    "type": field_type,
                    "value": value
                })
        if custom_fields is not None:
            data["custom"] = []
            for field_type, value in custom_fields.items():
                if type(value) is not list:
                    value = [value]
                data["fields"].append({
                    "label": field_type,
                    "type": field_type,
                    "value": value
                })

        return Record({
            "recordUid": uid,
            "data": CryptoUtils.encrypt_aes(json.dumps(data).encode(), RecordMaker.secret)
        }, RecordMaker.secret)

    @staticmethod
    def make_file(uid, title, files=None):

        if files is None:
            files = []

        file_refs = []
        file_parts = []
        for file in files:
            file_uid = str(uuid.uuid4())
            d = {
                "name": file.get("name"),
                "title": file.get("title", file.get("name")),
                "size": file.get("size", 123),
                "lastModified": file.get("last_modified", int(time.time())),
                "type": file.get("type", "plain/text"),
            }
            data = json.dumps(d)

            file_refs.append(file_uid)
            file_data = {
                "fileUid": file_uid,
                "fileKey": base64.b64encode(CryptoUtils.encrypt_aes(RecordMaker.secret, RecordMaker.secret)).decode(),
                "data": base64.b64encode(CryptoUtils.encrypt_aes(data.encode(), RecordMaker.secret)).decode(),
                "url": file.get("url", "http://localhost/{}".format(file_uid)),
                "thumbnailUrl": None
            }
            file_parts.append(file_data)

            file_content = file.get("data", "THIS IS FAKE DATA")
            RecordMaker.url_data[file_data["url"]] = CryptoUtils.encrypt_aes(file_content.encode(), RecordMaker.secret)

        r = None
        try:
            r = Record({
                "recordUid": uid,
                "data": CryptoUtils.encrypt_aes(json.dumps({
                    "title": title,
                    "type": "file",
                    "fields": [
                        {"type": "fileRef", "value": file_refs},
                    ],
                }).encode(), RecordMaker.secret),
                "files": file_parts
            }, RecordMaker.secret)
        except Exception as err:
            print(">>>>", err)
            traceback.print_exc()

        return r

    @staticmethod
    def get_url_data(url):
        ret = RecordMaker.url_data.get(url)
        return ret
