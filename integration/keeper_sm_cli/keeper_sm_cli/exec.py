import os
import sys
import subprocess
from keepercommandersm.core import Commander
import re


class Exec:

    def __init__(self, cli):
        self.cli = cli

    def env_replace(self):

        # keeper://<UID>/field/<type>
        # keeper://<UID>/custom_field/<label>
        # keeper://<UID>/file/<file_id>

        # Get a list of unique UID to get in one shot.
        uids = []
        for _, env_value in os.environ.items():
            if env_value.startswith(Commander.notation_prefix) is True:
                parts = env_value.split('//')
                (uid, _, _) = parts[1].split('/')
                if uid not in uids:
                    uids.append(uid)

        # Get the record and place them in a lookup by UID
        record_lookup = {}
        records = self.cli.client.get_secrets(uids)
        for record in records:
            record_lookup[record.uid] = record

        for env_key, env_value in os.environ.items():
            if env_value.startswith(Commander.notation_prefix) is True:
                parts = env_value.split('//')
                (uid, file_type, key) = parts[1].split('/')

                if file_type == "field":
                    value = record_lookup[uid].field(key, single=True)
                elif file_type == "custom_field":
                    value = record_lookup[uid].custom_field(key, single=True)
                elif file_type == "file":
                    value = record_lookup[uid].download_file_by_title(key)
                else:
                    raise ValueError("Field type of {} is not value.".format(file_type))
                os.environ["_" + env_key] = "_" + env_value
                os.environ[env_key] = value

    @staticmethod
    def execute(cmd, capture_output=False):

        full_cmd = " ".join(cmd)

        if len(cmd) == 0:
            sys.stderr.write("Cannot execute command, it's missing.\n")
            sys.exit(1)
        else:
            try:
                completed = subprocess.run(cmd, capture_output=capture_output)
            except OSError as err:
                message = str(err)
                if (re.search(r'WinError 193', message) is not None and
                        re.search(r'\.ps1', full_cmd, re.IGNORECASE) is not None):
                    sys.exit("Cannot execute command. If this was a powershell script, please use the command"
                             " 'powershell {}'".format(full_cmd))
                else:
                    sys.exit("Cannot execute command: {}".format(message))
            except Exception as err:
                sys.exit("Cannot execute command: {}".format(err))

            if completed.returncode != 0:
                exit(completed.returncode)
            if capture_output is True:
                print(completed.stdout)
