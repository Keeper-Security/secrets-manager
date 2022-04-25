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


from . import KeeperAnsible
import argparse
import sys
import os
import platform
import importlib_metadata
import keeper_secrets_manager_core
import logging
import ansible


def _config():
    plugins = os.path.join(os.path.dirname(__file__), "plugins")
    action_plugin_dir = os.path.join(plugins, "action_plugins")
    lookup_plugin_dir = os.path.join(plugins, "lookup_plugins")

    # Cleaver way of detecting if stdout is being piped into a file or not. If we are piping into a
    # file, then don't show the stderr message.
    if os.fstat(0) == os.fstat(1):
        print("\n# Below are the directory paths to action and lookup plugins.", file=sys.stderr)

    # Ansible doesn't really work on Windows, however include this anyways for the cleaver DevOp.
    if platform.system() == 'Windows':
        is_power_shell = len(os.getenv('PSModulePath', '').split(os.pathsep)) >= 3
        if is_power_shell is True:
            print('$env:ANSIBLE_ACTION_PLUGINS = "{}"'.format(action_plugin_dir))
            print('$env:ANSIBLE_LOOKUP_PLUGINS = "{}"'.format(lookup_plugin_dir))
        else:
            print('set ANSIBLE_ACTION_PLUGINS={}'.format(action_plugin_dir))
            print('set ANSIBLE_LOOKUP_PLUGINS={}'.format(lookup_plugin_dir))
    else:
        print("ANSIBLE_ACTION_PLUGINS={}".format(action_plugin_dir))
        print("ANSIBLE_LOOKUP_PLUGINS={}".format(lookup_plugin_dir))


def _version():
    # Unit test do not know their version
    versions = {
        "keeper-secrets-manager-ansible": "Unknown",
        "keeper-secrets-manager-core": "Unknown",
        "ansible": "Unknown"
    }
    for module in versions:
        try:
            versions[module] = importlib_metadata.version(module)
        except importlib_metadata.PackageNotFoundError:
            pass

    print()
    print("Python Version: {}".format(".".join([
        str(sys.version_info.major),
        str(sys.version_info.minor),
        str(sys.version_info.micro)
    ])))
    print("Python Install: {}".format(sys.executable))
    print("Plugin Version: {}".format(versions["keeper-secrets-manager-ansible"]))
    print("Plugin Install: {}".format(os.path.dirname(os.path.realpath(__file__))))
    print("SDK Version: {}".format(versions["keeper-secrets-manager-core"]))
    print("SDK Install: {}".format(os.path.dirname(os.path.realpath(keeper_secrets_manager_core.__file__))))
    print("Ansible Version: {}".format(versions["ansible"]))
    print("Ansible Install: {}".format(os.path.dirname(os.path.realpath(ansible.__file__))))
    print("ANSIBLE_ACTION_PLUGINS env is {}".format(os.environ.get("ANSIBLE_ACTION_PLUGINS", "Not Set")))
    print("ANSIBLE_LOOKUP_PLUGINS env is {}".format(os.environ.get("ANSIBLE_LOOKUP_PLUGINS", "Not Set")))


def _init(args):
    task_args = {
        "keeper_force_config_write": True
    }
    if args.token is not None:
        task_args["keeper_token"] = args.token
    if args.config_file is not None:
        task_args["keeper_config_file"] = args.config_file

    if task_args.get("keeper_token") is not None and ":" in task_args["keeper_token"]:
        task_args["keeper_hostname"], task_args["keeper_token"] = task_args["keeper_token"].split(":")

    try:
        keeper_ansible = KeeperAnsible(task_args)
        keeper_ansible.client.get_secrets()
        if keeper_ansible.config_created is True:
            print("Config file created at location {}".format(keeper_ansible.config_file))
    except Exception as err:
        sys.exit("Keeper Ansible had an error: {}".format(err))


def main(*args):
    parser = argparse.ArgumentParser(description='Ansible config generator')
    parser.add_argument('--token', type=str, required=False, help='One time access token')
    parser.add_argument('--config-file', type=str, help='Config file name', required=False)
    parser.add_argument('--config', help='Get configuration information', action='store_true')
    parser.add_argument('--version', help='Get version information', action='store_true')
    parsed_args = parser.parse_args(*args)

    # This is use show the location of the plugin directories
    if parsed_args.config is True:
        _config()
    elif parsed_args.version is True:
        _version()
    else:
        _init(parsed_args)


if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR)
    main(sys.argv[1:])
