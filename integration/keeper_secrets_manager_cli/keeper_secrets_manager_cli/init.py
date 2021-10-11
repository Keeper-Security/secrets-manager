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

import yaml
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from .export import Export
import subprocess
import sys


class Init:

    def __init__(self, cli, token, hostname=None, skip_ssl_verify=False):
        self.cli = cli
        self.token = token
        self.skip_ssl_verify = skip_ssl_verify

        self.config = InMemoryKeyValueStorage()
        redeem_sm = SecretsManager(config=self.config, token=token, hostname=hostname,
                                   verify_ssl_certs=not skip_ssl_verify)
        redeem_sm.get_secrets()

        self.config_dict = {}
        for e in ConfigKeys:
            if self.config.contains(e):
                self.config_dict[e.value] = self.config.get(e)

    def get_k8s(self, name, namespace, apply=False, immutable=False):

        base64_config = Export(config=self.config_dict, file_format="json", plain=False).run()

        if apply is True:
            subprocess.run([
                "kubectl", "create", "secret", "generic", name,
                "--from-literal=config={}".format(base64_config.decode())
            ])
            print("Created secret for KSM config.", file=sys.stderr)
        else:
            secret = {
                "apiVersion": "v1",
                "data": {
                    "config": base64_config.decode()
                },
                "kind": "Secret",
                "metadata": {
                    "name": name,
                    "namespace": namespace
                },
                "type": "Opaque"
            }

            # Kubernetes v1.21
            if immutable is True:
                secret["immutable"] = True

            print("", file=sys.stderr)
            self.cli.output(yaml.dump(secret))
            print("", file=sys.stderr)

    def get_json(self, plain=False):

        config_str = Export(config=self.config_dict, file_format="json", plain=plain).run()

        print("", file=sys.stderr)
        self.cli.output(config_str)
        print("", file=sys.stderr)
