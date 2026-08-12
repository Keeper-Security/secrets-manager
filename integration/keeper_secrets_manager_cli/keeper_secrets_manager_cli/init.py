# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
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
from .exception import KsmCliException
import re
import subprocess
import sys
import yaml


# RFC 1123 subdomain, the rule Kubernetes applies to Secret names. Enforced
# before the name reaches kubectl, which would otherwise read a value starting
# with '-' as one of its own flags. fullmatch (not match) so a trailing
# newline can't sneak past the end anchor.
K8S_NAME_PATTERN = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$')
K8S_NAME_MAX_LENGTH = 253
K8S_NAME_ERROR = (
    "must consist of lowercase alphanumeric characters, '-' or '.', with each "
    "'.'-separated label starting and ending with an alphanumeric character, "
    "and be at most 253 characters total."
)


def is_valid_k8s_name(name):
    return len(name) <= K8S_NAME_MAX_LENGTH and bool(K8S_NAME_PATTERN.fullmatch(name))


class QuotedStr(str):
    pass


def _represent_quoted_str(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="'")


class QuotingSafeDumper(yaml.SafeDumper):
    pass


QuotingSafeDumper.add_representer(QuotedStr, _represent_quoted_str)


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

        if not is_valid_k8s_name(name):
            raise KsmCliException("Invalid Kubernetes secret name '{}': {}".format(name, K8S_NAME_ERROR))

        base64_config = Export(config=self.config, file_format="json", plain=False).run()

        if apply is True:
            subprocess.run([
                "kubectl", "create", "secret", "generic", name,
                "--from-literal=config={}".format(base64_config.decode())
            ])
            print("Created secret for KSM config.", file=sys.stderr)
        else:
            # Build the manifest as a dict and serialize with a YAML library rather
            # than string formatting, so name and namespace are always emitted as
            # properly encoded scalars and cannot inject additional manifest content.
            manifest = {
                "apiVersion": "v1",
                "data": {"config": base64_config.decode()},
                "kind": "Secret",
                "metadata": {
                    "name": QuotedStr(name),
                    "namespace": QuotedStr(namespace),
                },
                "type": "Opaque",
            }
            # Kubernetes v1.21
            if immutable is True:
                manifest["immutable"] = True

            # Quoted so names that are legal in Kubernetes but ambiguous in YAML 1.1
            # (y, n, 1e5, ...) aren't misread by kubectl's parser as bool/number.
            secret = yaml.dump(
                manifest, Dumper=QuotingSafeDumper, default_flow_style=False, sort_keys=False
            ).rstrip("\n")

            print("", file=sys.stderr)
            self.cli.output(secret)
            print("", file=sys.stderr)

    def get_json(self, plain=False):

        config_str = Export(config=self.config, file_format="json", plain=plain).run()

        print("", file=sys.stderr)
        self.cli.output(config_str)
        print("", file=sys.stderr)
