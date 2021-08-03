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
import ansible


def main():
    parser = argparse.ArgumentParser(description='Ansible config generator')
    parser.add_argument('--keeper_token', metavar='-t', type=str, required=False, help='client key')
    parser.add_argument('--keeper_config_file', metavar='--cf', type=str, help='config file name', required=False)
    parser.add_argument('--keeper_hostname', metavar='--host', type=str, help='host name', required=False)
    parser.add_argument('--config', help='Get configuration information', action='store_true')
    parser.add_argument('--version', help='Get version information', action='store_true')
    args = parser.parse_args()

    # This is use show the location of the plugin directories
    if args.config is True:
        plugins = os.path.join(os.path.dirname(__file__), "plugins")
        action_plugin_dir = os.path.join(plugins, "action_plugins")
        lookup_plugin_dir = os.path.join(plugins, "lookup_plugins")

        # Cleaver way of detecting if stdout is being piped into a file or not. If we are piping into a
        # file, then don't show the stderr message.
        if os.fstat(0) == os.fstat(1):
            print("\n# Below are the directory paths to action and lookup plugins.", file=sys.stderr)

        if platform.system() == 'Windows':
            is_power_shell = len(os.getenv('PSModulePath', '').split(os.pathsep)) >= 3
            if is_power_shell is True:
                print('$env:DEFAULT_ACTION_PLUGIN_PATH = "{}"'.format(action_plugin_dir))
                print('$env:DEFAULT_LOOKUP_PLUGIN_PATH = "{}"'.format(lookup_plugin_dir))
            else:
                print('setx DEFAULT_ACTION_PLUGIN_PATH "{}"'.format(action_plugin_dir))
                print('setx DEFAULT_LOOKUP_PLUGIN_PATH "{}"'.format(lookup_plugin_dir))
        else:
            print("DEFAULT_ACTION_PLUGIN_PATH={}".format(action_plugin_dir))
            print("DEFAULT_LOOKUP_PLUGIN_PATH={}".format(lookup_plugin_dir))
        sys.exit(0)

    if args.version is True:

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
        print("DEFAULT_ACTION_PLUGIN_PATH is {}".format(os.environ.get("DEFAULT_ACTION_PLUGIN_PATH", "Not Set")))
        print("DEFAULT_LOOKUP_PLUGIN_PATH is {}".format(os.environ.get("DEFAULT_LOOKUP_PLUGIN_PATH", "Not Set")))
        sys.exit(0)

    # We want to create JSON config file so force it.
    task_args = {
        "keeper_force_config_write": True
    }
    if args.keeper_token is not None:
        task_args["keeper_token"] = args.keeper_token
    if args.keeper_config_file is not None:
        task_args["keeper_config_file"] = args.keeper_config_file
    if args.keeper_hostname is not None:
        task_args["keeper_hostname"] = args.keeper_hostname

    try:
        keeper_ansible = KeeperAnsible(task_args)

        if keeper_ansible.config_created is True:
            print("Config file created at location {}".format(keeper_ansible.config_file))
    except Exception as err:
        sys.exit("Keeper Ansible had an error: {}".format(err))


if __name__ == "__main__":
    main()
