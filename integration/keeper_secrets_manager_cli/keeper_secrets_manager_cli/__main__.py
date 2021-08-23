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
from click_help_colors import HelpColorsGroup, HelpColorsCommand
from colorama import Fore, Style
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
from colorama import init


def _get_cli(**kwargs):
    return KeeperCli(**kwargs)


def base_command_help(f):
    doc = f.__doc__

    # Unit test do not know their version
    version = "Unknown"
    try:
        version = importlib_metadata.version("keeper-secrets-manager-cli")
    except importlib_metadata.PackageNotFoundError:
        pass

    f.__doc__ = "{} Version: {} ".format(
        Fore.RED + doc + Style.RESET_ALL,
        Fore.YELLOW + version + Style.RESET_ALL
    )
    return f


# MAIN GROUP
@click.group(
    cls=HelpColorsGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
@click.option('--ini-file', type=str, help="INI config file.")
@click.option('--profile-name', '-p', type=str, help='Config profile')
@click.option('--output', '-o', type=str, help='Output [stdout|stderr|filename]', default='stdout')
@click.option('--color/--no-color', '-c/-nc', default=None, help="Use color in table views, where applicable.")
@click.pass_context
@base_command_help
def cli(ctx, ini_file, profile_name, output, color):

    """Keeper Secrets Manager CLI
    """

    try:
        ctx.obj = {
            "cli": _get_cli(ini_file=ini_file, profile_name=profile_name, output=output, use_color=color),
            "ini_file": ini_file,
            "profile_name": profile_name,
            "output": output,
            "use_color": color
        }
    except FileNotFoundError as _:
        sys.exit("Could not find the INI file specified on the top level command. If you are running the init"
                 " sub-command, specify the INI file on the sub-command parameters instead on the top level command.")
    except Exception as err:
        # Set KSM_DEBUG to get a stack trace. Secret env var.
        if os.environ.get("KSM_DEBUG") is not None:
            print(traceback.format_exc(), file=sys.stderr)
        sys.exit("Could not run the command. Got the error: {}".format(err))


# PROFILE GROUP


@click.group(
    name='profile',
    cls=HelpColorsGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
def profile_command():
    """Commands for profile management."""
    pass


@click.command(
    name='init',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
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


@click.command(
    name='list',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--json', is_flag=True, help='Return secret as JSON')
@click.pass_context
def profile_list_command(ctx, json):
    """List all profiles."""

    output = "text"
    if json is True:
        output = "json"

    Profile(cli=ctx.obj["cli"]).list_profiles(output=output)


@click.command(
    name='active',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.argument('profile-name', type=str, required=True, nargs=1)
@click.pass_context
def profile_active_command(ctx, profile_name):
    """Set the active profile."""
    Profile(cli=ctx.obj["cli"]).set_active(
        profile_name=profile_name
    )


@click.command(
    name='export',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--plain', is_flag=True, help='Export the config non-Base64 encoded.')
@click.argument('profile-name', type=str, required=False, nargs=1)
@click.pass_context
def profile_export_command(ctx, plain, profile_name):
    """Create a new config file from a profile."""
    Profile(cli=ctx.obj["cli"]).export_config(
        plain=plain,
        profile_name=profile_name
    )


@click.command(
    name='import',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--output-file', '-f', type=str, required=False,
              help='Create the config in a specific file location.')
@click.argument('config-base64', type=str, required=True, nargs=1)
@click.pass_context
def profile_import_command(ctx, output_file, config_base64):
    """Import an encrypted config file."""
    Profile(cli=ctx.obj["cli"]).import_config(
        file=output_file,
        config_base64=config_base64
    )

profile_command.add_command(profile_init_command)
profile_command.add_command(profile_list_command)
profile_command.add_command(profile_active_command)
profile_command.add_command(profile_export_command)
profile_command.add_command(profile_import_command)

# SECRET GROUP


@click.group(
    name='secret',
    cls=HelpColorsGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
@click.pass_context
def secret_command(ctx):
    """Commands for secrets."""
    ctx.obj["secret"] = Secret(cli=ctx.obj["cli"])


@click.command(
    name='list',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
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
        use_color=ctx.obj["cli"].use_color
    )


@click.command(
    name='get',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--uid', '-u', type=str, multiple=True, help='Unique identifier of record.')
@click.option('--title', '-t', type=str, multiple=True, help='Title of record.')
@click.option('--field', '-f', type=str, help='Field to get.')
@click.option('--query', '-q', type=str, help='Perform a JSONPath query on results.')
@click.option('--json', is_flag=True, help='Return secret as JSON')
@click.option('--raw', is_flag=True, help="Remove quotes on return quote text.")
@click.option('--force-array', is_flag=True, help="Return secrets as array even if a single record.")
@click.option('--unmask', is_flag=True, help="Show password like values in table views.")
@click.pass_context
def secret_get_command(ctx, uid, title, field, query, json, raw, force_array, unmask):
    """Get secret record(s)."""

    output = "text"
    if json is True:
        output = "json"

    total_query = len(uid) + len(title)

    if total_query == 0:
        sys.exit("No uid or title specified for secret get command.")

    if total_query > 1 and field is not None:
        sys.exit("Cannot perform field search on multiple records. Only choose one uid/title.")

    ctx.obj["secret"].query(
        uids=uid,
        titles=title,
        field=field,
        jsonpath_query=query,
        output_format=output,
        raw=raw,
        force_array=force_array,
        load_references=True,
        unmask=unmask,
        use_color=ctx.obj["cli"].use_color
    )


@click.command(
    name='notation',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.argument('text', type=str, nargs=1)
@click.pass_context
def secret_notation_command(ctx, text):
    """Get secret record via notation."""
    ctx.obj["secret"].get_via_notation(notation=text)


@click.command(
    name='update',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
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


@click.command(
    name='download',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
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


@click.command(
    name='exec',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--capture-output', is_flag=True, help='Capture the output and display upon cmd exit.')
@click.option('--inline', is_flag=True, help='Replace include placeholders.')
@click.argument('cmd', type=str, nargs=-1)
@click.pass_context
def exec_command(ctx, capture_output, inline, cmd):
    """Wrap an application and expose secrets in environmental variables."""
    ex = Exec(cli=ctx.obj["cli"])
    ex.execute(cmd=cmd, capture_output=capture_output, inline=inline)


# CONFIG COMMAND
@click.group(
    name='config',
    cls=HelpColorsGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
@click.pass_context
def config_command(ctx):
    """Configure the command line tool."""
    ctx.obj["profile"] = Profile(cli=ctx.obj["cli"])
    pass


@click.command(
    name='show',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.pass_context
def config_show_command(ctx):
    """Show current configuration."""
    ctx.obj["profile"].show_config()

@click.command(
    name='color',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--enable/--disable', required=True, help="Enable or disable color.")
@click.pass_context
def config_log_command(ctx, enable):
    """Enable or disable color"""
    ctx.obj["profile"].set_color(enable)


config_command.add_command(config_show_command)
config_command.add_command(config_log_command)


@click.command(
    name='version',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.pass_context
def version_command(ctx):
    """Get module versions and information."""

    # Unit test do not know their version
    versions = {
        "keeper-secrets-manager-core": "Unknown",
        "keeper-secrets-manager-cli": "Unknown"
    }
    for module in versions:
        try:
            versions[module] = importlib_metadata.version(module)
        except importlib_metadata.PackageNotFoundError:
            pass

    print("Python Version: {}".format(".".join([
        str(sys.version_info.major),
        str(sys.version_info.minor),
        str(sys.version_info.micro)
    ])))
    print("Python Install: {}".format(sys.executable))
    print("CLI Version: {}".format(versions["keeper-secrets-manager-cli"]))
    print("CLI Install: {}".format(os.path.dirname(os.path.realpath(__file__))))
    print("SDK Version: {}".format(versions["keeper-secrets-manager-core"]))
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
        # This init colors for Windows. CMD looks great. PS has no yellow :(
        init()
        cli(obj={"cli": None})
    except Exception as err:
        # Set KSM_DEBUG to get a stack trace. Secret env var.
        if os.environ.get("KSM_DEBUG") is not None:
            print(traceback.format_exc(), file=sys.stderr)
        sys.exit("ksm had a problem: {}".format(err))


if __name__ == '__main__':
    main()
