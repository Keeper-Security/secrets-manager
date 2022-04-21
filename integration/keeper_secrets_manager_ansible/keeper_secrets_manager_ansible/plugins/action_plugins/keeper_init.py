#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from ansible.plugins.action import ActionBase
from keeper_secrets_manager_ansible import KeeperAnsible
from keeper_secrets_manager_core.configkeys import ConfigKeys
from ansible.errors import AnsibleError
from distutils.util import strtobool
import json
import yaml
import re

DOCUMENTATION = r'''
---
module: keeper_init

short_description: Initialize a Keeper configuration using the one-time access token.

version_added: "1.0.1"

description:
    - Use the extra variable 'keeper_token' to pass in the one time access token.
    - The token can only be used once, so there is not reason to put it into any configuration file.
    - The configuration file output location can be set using the extra variable 'keeper_config_file'.
    - If 'keeper_config_file' is not defined, the configuration file will be written to the current directory.
    - By default, the configuration file will be a YAML file. If the extension of the 'keeper_config_file' is JSON, a 
      JSON file will be created.
author:
    - John Walstra
options:
  token:
    description:
    - The one-time access token.
    - This token can only be used once.
    - Hard coding the token into a role or playbook is not advised.
    - Best to set via extra variable passed to the playbook.
    type: str
    required: yes
  filename:
    description:
    - File path and name where to write the configuration file.
    - By default, a YAML file is created with key used by Ansible.
    - If the extension is JSON, the standard JSON config will be created.
    - If not set, a YAML configuration 
    type: str
    required: no
  show_config:
    description:
    - File path and name where to write the configuration file.
    - By default, a YAML file is created with key used by Ansible.
    - If the extension is JSON, the standard JSON config will be created.
    - If not set, a YAML configuration 
    type: str
    required: no    
'''

EXAMPLES = r'''
- name: Init the token
  keeper_init:
    token: XX:XXXXXXX
    keeper_config_file: /tmp/keeper_config.yml
'''

RETURN = r'''
keeper_client_id:
  description: Client ID for the application.
  returned: success
  sample: i31TDFtdZE .... oiCQ
keeper_private_key:
  description: Private key for the application.
  returned: success
  sample: MIGHAgEAMB .... JMJRzpE
keeper_app_key:
  description: Application key for the application.
  returned: success
  sample: zhLwB .... LPGY
keeper_app_owner_public_key:
  description: Public key that allows creation of records.
  returned: success
  version_added: '1.1.2' 
  sample: zhLwB .... LPGY
keeper_server_public_key_id:
  description: Id of the public key to use when sending request.
  returned: success
  sample: 10
keeper_hostname:
  description: Hostname to use ending request.
  returned: success
  sample: keepersecurity.com
'''


class ActionModule(ActionBase):

    @staticmethod
    def make_config(config, filename=None):

        config_dict = {}
        for enum_key, ansible_key in {"clientId": "keeper_client_id", "appKey": "keeper_app_key",
                                      "privateKey": "keeper_private_key",
                                      "serverPublicKeyId": "keeper_server_public_key_id",
                                      "appOwnerPublicKey": "keeper_app_owner_public_key",
                                      "hostname": "keeper_hostname"}.items():
            e = ConfigKeys.get_enum(enum_key)
            if config.contains(e):
                config_dict[ansible_key] = str(config.get(e))

        # If the file name is set, then save the config into a file. A JSON extension will make the standard
        # JSON config file that is usable across SDKs and integrations. Anything else will make a YAML file
        # with a config that has keys that Ansible can use.
        if filename is not None and filename != "":
            # If this a JSON file.
            if re.search(r'json$', filename) is not None:
                config_json_dict = {}
                for e in ConfigKeys:
                    if config.contains(e):
                        config_json_dict[e.value] = config.get(e)
                with open(filename, "w") as fh:
                    fh.write(json.dumps(config_json_dict, indent=4))
                    fh.close()
            # Else write the YAML file.
            else:
                with open(filename, "w") as fh:
                    fh.write(yaml.dump(config_dict))
                    fh.close()

        return config_dict

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)

        if task_vars is None:
            task_vars = {}

        # Only get the values from the values passed in with option.

        # We need the one time access token.
        token = self._task.args.get("token")
        if token is None or token == "":
            raise AnsibleError("The token is not set. Either set keeper_token extra vars or token on the action.")

        # If there is no filename, don't create a file
        config_file = self._task.args.get("filename")

        # Remove keeper_ keys from task vars. We only want to accept from other variables, like existing
        # configurations.
        for key in list(task_vars.keys()):
            if re.search("^{}".format(KeeperAnsible.KEY_PREFIX), key) is not None:
                task_vars.pop(key, None)

        if ":" in token:
            task_vars[KeeperAnsible.keeper_key(KeeperAnsible.HOSTNAME_KEY)], \
                task_vars[KeeperAnsible.keeper_key(KeeperAnsible.TOKEN_KEY)] = token.split(":")
        else:
            task_vars[KeeperAnsible.keeper_key(KeeperAnsible.TOKEN_KEY)] = token

        # We don't want a JSON, force the config to be in memory.
        keeper = KeeperAnsible(task_vars=task_vars, force_in_memory=True)

        # Don't load the entire vault, make a bad UID.
        try:
            keeper.client.get_secrets()
        except Exception as err:
            raise AnsibleError(str(err))

        config_dict = self.make_config(keeper.client.config, config_file)

        # Do we want to see the config in the ansible debug. By default, this is disabled.
        show_config = bool(strtobool(str(self._task.args.get("show_config", False))))
        if show_config is True:
            return config_dict
        else:
            return {}
