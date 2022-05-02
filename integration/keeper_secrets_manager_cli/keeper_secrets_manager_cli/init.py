# -*- coding: utf-8 -*-
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

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from .export import Export
from .config import Config
import subprocess
import sys


class Init:

    @staticmethod
    def get_client(config, token, hostname, verify_ssl_certs):
        return SecretsManager(config=config, token=token, hostname=hostname,
                              verify_ssl_certs=verify_ssl_certs)

    @staticmethod
    def init_config():
        return InMemoryKeyValueStorage()

    def __init__(self, cli, token, hostname=None, skip_ssl_verify=False):
        self.cli = cli
        self.token = token
        self.skip_ssl_verify = skip_ssl_verify

        redeem_sm = Init.get_client(config=Init.init_config(), token=token, hostname=hostname,
                                    verify_ssl_certs=not skip_ssl_verify)
        redeem_sm.get_secrets()
        in_memory_config = redeem_sm.config

        config = Config()
        config.set_profile("NA",
                           client_id=in_memory_config.get(ConfigKeys.KEY_CLIENT_ID),
                           private_key=in_memory_config.get(ConfigKeys.KEY_PRIVATE_KEY),
                           app_key=in_memory_config.get(ConfigKeys.KEY_APP_KEY),
                           hostname=in_memory_config.get(ConfigKeys.KEY_HOSTNAME),
                           app_owner_public_key=in_memory_config.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY),
                           server_public_key_id=in_memory_config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID))
        self.config = config.get_profile("NA")

    def get_k8s(self, name, namespace, apply=False, immutable=False):

        base64_config = Export(config=self.config, file_format="json", plain=False).run()

        if apply is True:
            subprocess.run([
                "kubectl", "create", "secret", "generic", name,
                "--from-literal=config={}".format(base64_config.decode())
            ])
            print("Created secret for KSM config.", file=sys.stderr)
        else:
            secret = "apiVersion: v1\n"\
                     "data: \n"\
                     "  config: {}\n"\
                     "kind: Secret\n"\
                     "metadata:\n"\
                     "  name: {}\n"\
                     "  namespace: {}\n"\
                     "type: Opaque".format(base64_config.decode(), name, namespace)

            # Kubernetes v1.21
            if immutable is True:
                secret += "\nimmutable: True\n"

            print("", file=sys.stderr)
            self.cli.output(secret)
            print("", file=sys.stderr)

    def get_json(self, plain=False):

        config_str = Export(config=self.config, file_format="json", plain=plain).run()

        print("", file=sys.stderr)
        self.cli.output(config_str)
        print("", file=sys.stderr)
