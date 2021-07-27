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

import click
from . import KeeperCli
from .exec import Exec
from .secret import Secret
from .profile import Profile
import sys
import os
import keeper_secrets_manager_core
import traceback
import importlib_metadata
from distutils.util import strtobool


def _get_cli(ini_file=None, profile_name=None, output=None):
    return KeeperCli(
        ini_file=ini_file,
        profile_name=profile_name,
        output=output
    )


def base_command_help(f):
    doc = f.__doc__

    # Unit test do not know their version
    version = "Unknown"
    try:
        version = importlib_metadata.version("keeper-secrets-manager-cli")
    except importlib_metadata.PackageNotFoundError:
        pass

    f.__doc__ = "{} Version: {} ".format(doc, version)
    return f


# MAIN GROUP
@click.group()
@click.option('--ini-file', type=str, help="INI config file.")
@click.option('--profile-name', '-p', type=str, help='Config profile')
@click.option('--output', '-o', type=str, help='Output [stdout|stderr|filename]', default='stdout')
@click.pass_context
@base_command_help
def cli(ctx, ini_file, profile_name, output):

    """Keeper Secrets Manager CLI
    """

    try:
        ctx.obj = {
            "cli": _get_cli(ini_file=ini_file, profile_name=profile_name, output=output),
            "ini_file": ini_file,
            "profile_name": profile_name,
            "output": output
        }
    except FileNotFoundError as _:
        sys.exit("Could not find the INI file specified on the top level command. If you are running the init"
                 " sub-command, specify the INI file on the sub-command parameters instead on the top level command.")
    except Exception as err:
        sys.exit("Could not run the command. Got the error: {}".format(err))


# PROFILE GROUP


@click.group(name='profile')
def profile_command():
    """Commands for profile management."""
    pass


@click.command(name='init')
@click.option('--token', '-t', type=str, required=True, help="The One Time Access Token.")
@click.option('--hostname', '-h', type=str, default="US", help="Hostname of secrets manager server.")
@click.option('--ini-file', type=str, help="INI config file to create.")
@click.option('--profile-name', '-p', type=str, help='Config profile to create.')
@click.pass_context
def profile_init_command(ctx, token, hostname, ini_file, profile_name):
    """Initialize a profile."""

    # Since the top level commands are available for all command, it might be confusing the init command since
    # it take
    if ctx.obj["ini_file"] is not None and ini_file is not None:
        print("NOTE: The INI file config was set on the top level command and also set on the init sub-command. The top"
              " level command parameter will be ignored for the init sub-command.", file=sys.stderr)

    Profile.init(
        token=token,
        server=hostname,
        ini_file=ini_file,
        profile_name=profile_name
    )


@click.command(name='list')
@click.option('--json', is_flag=True, help='Return secret as JSON')
@click.pass_context
def profile_list_command(ctx, json):
    """List all profiles."""

    output = "text"
    if json is True:
        output = "json"

    Profile(cli=ctx.obj["cli"]).list_profiles(output=output)


@click.command(name='active')
@click.argument('profile-name', type=str, required=True, nargs=1)
@click.pass_context
def profile_active_command(ctx, profile_name):
    """Set the active profile."""
    Profile(cli=ctx.obj["cli"]).set_active(
        profile_name=profile_name
    )


@click.command(name='export')
@click.option('--key', '-k', type=str, help='Encode config with a key')
@click.argument('profile-name', type=str, required=False, nargs=1)
@click.pass_context
def profile_export_command(ctx, key, profile_name):
    """Create a new config file from a profile."""
    Profile(cli=ctx.obj["cli"]).export_config(
        key=key,
        profile_name=profile_name
    )


@click.command(name='import')
@click.option('--key', '-k', type=str, required=True, help='Decode config with a key.')
@click.option('--output-file', '-f', type=str, required=False,
              help='Save the import config to a specific file location.')
@click.argument('enc-config', type=str, required=True, nargs=1)
@click.pass_context
def profile_import_command(ctx, key, output_file, enc_config):
    """Import an encrypted config file."""
    Profile(cli=ctx.obj["cli"]).import_config(
        key=key,
        file=output_file,
        enc_config=enc_config
    )


profile_command.add_command(profile_init_command)
profile_command.add_command(profile_list_command)
profile_command.add_command(profile_active_command)
profile_command.add_command(profile_export_command)
profile_command.add_command(profile_import_command)

# SECRET GROUP


@click.group(name='secret')
@click.pass_context
def secret_command(ctx):
    """Commands for secrets."""
    ctx.obj["secret"] = Secret(cli=ctx.obj["cli"])


@click.command(name='list')
@click.option('--uid', "-u", type=str, multiple=True)
@click.option('--json', is_flag=True, help='Return secret as JSON')
@click.pass_context
def secret_list_command(ctx, uid, json):
    """List all secrets."""

    output = "text"
    if json is True:
        output = "json"

    ctx.obj["secret"].secret_list(
        uids=uid,
        output_format=output,
    )


@click.command(name='get')
@click.option('--uid', '-u', required=True, type=str, multiple=True)
@click.option('--query', '-q', type=str, help='Perform a JSONPath query on results.')
@click.option('--json', is_flag=True, help='Return secret as JSON')
@click.option('--raw', is_flag=True, help="Remove quotes on return quote text.")
@click.option('--force-array', is_flag=True, help="Return secrets as array even if a single record.")
@click.pass_context
def secret_get_command(ctx, uid, query, json, raw, force_array):
    """Get secret record(s)."""

    output = "text"
    if json is True:
        output = "json"

    ctx.obj["secret"].query(
        uids=uid,
        jsonpath_query=query,
        output_format=output,
        raw=raw,
        force_array=force_array,
        load_references=True
    )


@click.command(name='notation')
@click.argument('text', type=str, nargs=1)
@click.pass_context
def secret_notation_command(ctx, text):
    """Get secret record via notation."""
    ctx.obj["secret"].get_via_notation(notation=text)


@click.command(name='update')
@click.option('--uid', '-u', required=True, type=str)
@click.option('--field', type=str, multiple=True)
@click.option('--custom-field', type=str, multiple=True)
@click.pass_context
def secret_update_command(ctx, uid, field, custom_field):
    """Update an existing record."""
    ctx.obj["secret"].update(
        uid=uid,
        fields=field,
        custom_fields=custom_field,
    )


@click.command(name='download')
@click.option('--uid', '-u', required=True, type=str, help="UID of the secret.")
@click.option('--name', required=True, type=str, help='Name of the file to download.')
@click.option('--file-output', required=True, type=str, help="Where to write the file's content. "
                                                             "[filename|stdout|stderr]")
@click.option('--create-folders', is_flag=True, help='Create folder for filename path.')
@click.pass_context
def secret_download_command(ctx, uid, name, file_output, create_folders):
    """Download a file from a secret record."""
    ctx.obj["secret"].download(
        uid=uid,
        name=name,
        file_output=file_output,
        create_folders=create_folders
    )


secret_command.add_command(secret_list_command)
secret_command.add_command(secret_get_command)
secret_command.add_command(secret_notation_command)
secret_command.add_command(secret_update_command)
secret_command.add_command(secret_download_command)


# EXEC COMMAND


@click.command(name='exec')
@click.option('--capture-output', is_flag=True, help='Capture the output and display upon cmd exit.')
@click.option('--inline', is_flag=True, help='Replace include placeholders.')
@click.argument('cmd', type=str, nargs=-1)
@click.pass_context
def exec_command(ctx, capture_output, inline, cmd):
    """Wrap an application and expose secrets in environmental variables."""
    ex = Exec(cli=ctx.obj["cli"])
    ex.execute(cmd=cmd, capture_output=capture_output, inline=inline)


# CONFIG COMMAND
@click.group(name='config')
@click.pass_context
def config_command(ctx):
    """Configure the command line tool."""
    ctx.obj["profile"] = Profile(cli=ctx.obj["cli"])
    pass


@click.command(name='show')
@click.pass_context
def config_show_command(ctx):
    """Show current configuration."""
    ctx.obj["profile"].show_config()


@click.command(name='log')
@click.option('--level',  '-l', type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "NOTSET"]),
              help="Level of message or error to display")
@click.pass_context
def config_log_command(ctx, level):
    """Set the log level"""
    if level is not None:
        ctx.obj["profile"].set_log_level(level)


config_command.add_command(config_show_command)
config_command.add_command(config_log_command)


@click.command(name='version')
@click.pass_context
def version_command(ctx):
    """Get module versions and information."""

    # Unit test do not know their version
    cli_version = "Unknown"
    sdk_version = "Unknown"
    try:
        sdk_version = importlib_metadata.version("keeper-secrets-manager-core")
        cli_version = importlib_metadata.version("keeper-secrets-manager-cli")
    except importlib_metadata.PackageNotFoundError:
        pass

    print("Python Version: {}".format(".".join([
        str(sys.version_info.major),
        str(sys.version_info.minor),
        str(sys.version_info.micro)
    ])))
    print("Python Install: {}".format(sys.executable))
    print("CLI Version: {}".format(cli_version))
    print("CLI Install: {}".format(os.path.dirname(os.path.realpath(__file__))))
    print("SDK Version: {}".format(sdk_version))
    print("SDK Install: {}".format(os.path.dirname(os.path.realpath(keeper_secrets_manager_core.__file__))))
    print("Config file: {}".format(ctx.obj["cli"].profile.ini_file))


# TOP LEVEL COMMANDS
cli.add_command(profile_command)
cli.add_command(secret_command)
cli.add_command(exec_command)
cli.add_command(config_command)
cli.add_command(version_command)


def main():
    try:
        cli(obj={"cli": None})
    except Exception as err:
        # Set KSM_DEBUG to get a stack trace. Secret env var.
        if strtobool(os.environ.get("KSM_DEBUG", "FALSE")) == 1:
            print(traceback.format_exc(), file=sys.stderr)
        sys.exit("ksm had a problem: {}".format(err))


if __name__ == '__main__':
    main()
