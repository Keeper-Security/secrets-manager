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
from click_repl import repl, exit as repl_exit
from colorama import Fore, Style, init
from . import KeeperCli
from .exception import KsmCliException
from .exec import Exec
from .secret import Secret
from .profile import Profile
from .init import Init
import sys
import os
import keeper_secrets_manager_core
import traceback
import importlib_metadata
import difflib
import typing as t
from update_checker import UpdateChecker


# NOTE: For the CLI, all groups and command are lowercase. All arguments are lower case, so you cannot use
# -n and -N for an arg flag. If you add a command, you need to add it to the list of known commands so we can
# do a best match.


class AliasedGroup(HelpColorsGroup):
    known_commands = [
        "config",
        "color",
        "show",
        "exec",
        "profile",
        "active",
        "export",
        "import",
        "init",
        "secret",
        "totp",
        "download",
        "get",
        "list",
        "notation",
        "update",
        "version",
        "password",
        "template",
        "add",
        "editor",
        "field",
        "record",
        "file",
        "cache",
        "record-type-dir"
    ]

    alias_commands = {
        "c": "config",
        "e": "exec",
        "p": "profile",
        "i": "init",
        "s": "secret",
        "g": "get",
        "l": "list",
        "t": "totp",
        "d": "download",
        "n": "notation",
        "u": "update",
        "v": "version",
        "exit": "quit",
        "pass": "password",
        "q": "quit",
        "help": "--help"
    }

    def get_command(self, ctx, cmd_name):

        """ Find the best matching command

        If the user mistypes a command, find the best matching command. Also lowercase the command if they type
        in mixed case.
        """

        # All commands are lower case, lowercase in case user used mixed case.
        cmd_name = cmd_name.lower()

        # Is the command an alias?
        if cmd_name in AliasedGroup.alias_commands:
            cmd_name = AliasedGroup.alias_commands[cmd_name]
        # Else if the command is not in known command list, find the best match.
        elif cmd_name not in AliasedGroup.known_commands:
            best_command = None
            best_score = 0
            for command in AliasedGroup.known_commands:
                seq = difflib.SequenceMatcher(a=cmd_name, b=command)
                if seq.ratio() > best_score:
                    best_score = seq.ratio()
                    best_command = command

            if best_score > 0.50:
                cmd_name = best_command
        return super().get_command(ctx, cmd_name)

    def parse_args(self, ctx, args: t.List[str]):

        """ Convert any argument case-insensitive.

        Lowercase any argument that starts with a -, except if it's 22 characters long. If it's 22 chars long, it
        most likely a record uid that starts a with -.
        """

        new_args: t.List[str] = []
        for item in args:
            # 22 is the length of the UID. We don't want to change the case of that if it starts with a -
            if item.startswith("-") and len(item) != 22:
                item = item.lower()
            new_args.append(item)

        return super().parse_args(ctx, new_args)


def _get_cli(**kwargs):
    return KeeperCli(**kwargs)


def get_versions():

    # Unit test do not know their version
    versions = {
        "keeper-secrets-manager-core": "Unknown",
        "keeper-secrets-manager-cli": "Unknown"
    }

    # Inside of the binaries, it's hard to get versions # so we create a versions.txt file in the build.
    # If the versions.txt file exists, read the versions from that file.

    ksm_bin_path = os.path.dirname(__file__)
    # Get the directory of the executable file. If last directory is keeper_secrets_manager_cli, get the parent
    # directory. There is no keeper_secrets_manager_cli directory.
    if ksm_bin_path.endswith("keeper_secrets_manager_cli") is True:
        ksm_bin_path = os.path.dirname(ksm_bin_path)
    version_path = os.path.join(ksm_bin_path, "versions.txt")
    if os.path.isfile(version_path) is True:
        with open(version_path, "r") as fh:
            lines = fh.readlines()
            for line in lines:
                # The versions file follows the requirements.txt file format.
                parts = line.split("==")
                if parts[0] in versions:
                    # Remove the line feed at the end. Just makes the "version" command output have extra lines.
                    versions[parts[0]] = parts[1].replace('\n', '').replace('\r', '')
            fh.close()
    # Else detect the versions from the site-packages
    else:
        for module in versions:
            try:
                versions[module] = importlib_metadata.version(module)
            except importlib_metadata.PackageNotFoundError:
                pass

    return versions


def update_available(module, versions=None):

    if versions is None:
        versions = get_versions()
    return UpdateChecker().check(module, versions[module])


def base_command_help(f):
    doc = f.__doc__

    versions = get_versions()
    cli_version = versions.get("keeper-secrets-manager-cli")
    sdk_version = versions.get("keeper-secrets-manager-core")

    doc = "{} Version: {} ".format(
        Fore.RED + doc + Style.RESET_ALL,
        Fore.YELLOW + cli_version + Style.RESET_ALL
    )
    try:
        # The __doc__ stuff gets formatted so new line don't work, however long spaces will.
        spacer = " " * 80
        update = update_available("keeper-secrets-manager-cli", versions)
        if update is not None:
            doc += spacer + "Version {} is available for the CLI".format(update.available_version)

        if sdk_version != "Unknown":
            update = update_available("keeper-secrets-manager-core", versions)
            if update is not None:
                doc += spacer + "Version {} is available for the SDK".format(update.available_version)
    except (Exception,):
        pass

    f.__doc__ = doc

    return f


# MAIN GROUP
@click.group(
    cls=AliasedGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
@click.option('--ini-file', type=str, help="INI config file.")
@click.option('--profile-name', '-p', type=str, help='Config profile')
@click.option('--output', '-o', type=str, help='Output [stdout|stderr|filename]', default='stdout')
@click.option('--color/--no-color', '-c/-nc', default=None, help="Use color in table views, where applicable.")
@click.option('--cache/--no-cache', default=None, help="Enable/disable record caching.")
@click.pass_context
@base_command_help
def cli(ctx, ini_file, profile_name, output, color, cache):
    """Keeper Secrets Manager CLI
    """
    ctx.obj = {
        "cli": _get_cli(ini_file=ini_file, profile_name=profile_name, output=output, use_color=color, use_cache=cache),
        "ini_file": ini_file,
        "profile_name": profile_name,
        "output": output,
        "use_color": color,
        "use_cache": cache
    }


# PROFILE GROUP

@click.group(
    name='profile',
    cls=AliasedGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
def profile_command():
    """Manage local client device profiles"""
    pass


@click.command(
    name='init',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--token', '-t', type=str, help="The One Time Access Token.")
@click.option('--hostname', '-h', type=str, help="Hostname of secrets manager server.")
@click.option('--ini-file', type=str, help="INI config file to create.")
@click.option('--profile-name', '-p', type=str, help='Config profile to create.')
@click.argument('token-arg', type=str, nargs=-1)
@click.pass_context
def profile_init_command(ctx, token, hostname, ini_file, profile_name, token_arg):
    """Initialize a profile"""

    if token is None and len(token_arg) > 0:
        token = token_arg[0]
    if token is None:
        raise KsmCliException("A one time access token is required either as a command parameter or an argument.")

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
    """List all profiles"""

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
    """Set the active profile"""
    Profile(cli=ctx.obj["cli"]).set_active(
        profile_name=profile_name
    )


@click.command(
    name='export',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--plain', is_flag=True, help='Export the config not base64 encoded.')
@click.option('--file-format', type=click.Choice(['ini', 'json'], case_sensitive=False), default='ini',
              help='File format to export.')
@click.argument('profile-name', type=str, required=False, nargs=1)
@click.pass_context
def profile_export_command(ctx, plain, file_format, profile_name):
    """Create a new config file from a profile"""
    Profile(cli=ctx.obj["cli"]).export_config(
        plain=plain,
        file_format=file_format,
        profile_name=profile_name
    )


@click.command(
    name='import',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--output-file', '-f', type=str, required=False, help='Create the config in a specific file location.')
@click.argument('config-base64', type=str, required=True, nargs=1)
@click.pass_context
def profile_import_command(ctx, output_file, config_base64):
    """Import an encrypted config file"""
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
    cls=AliasedGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
@click.pass_context
def secret_command(ctx):
    """Commands for secrets"""
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
    """List all secrets"""

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
@click.option('--force-array', is_flag=True, help="Return secrets as array even if a single record.")
@click.option('--unmask', is_flag=True, help="Show password like values in table views.")
@click.option('--inflate/--deflate', default=True, help="Load in outside records.")
@click.argument('extra-uid', type=str, nargs=-1)
@click.pass_context
def secret_get_command(ctx, uid, title, field, query, json, force_array, unmask, inflate, extra_uid):
    """Get secret record(s)"""

    uid_list = []
    if uid is not None:
        for u in uid:
            uid_list.append(u)
    if extra_uid is not None:
        for u in extra_uid:
            uid_list.append(u)

    output = "text"
    if json is True:
        output = "json"

    total_query = len(uid_list) + len(title)

    if total_query == 0:
        raise KsmCliException("No uid or title specified for secret get command.")

    if total_query > 1 and field is not None:
        raise KsmCliException("Cannot perform field search on multiple records. Only choose one uid/title.")

    ctx.obj["secret"].query(
        uids=uid_list,
        titles=title,
        field=field,
        jsonpath_query=query,
        output_format=output,
        force_array=force_array,
        load_references=True,
        unmask=unmask,
        use_color=ctx.obj["cli"].use_color,
        inflate=inflate
    )


@click.command(
    name='notation',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.argument('text', type=str, nargs=1)
@click.pass_context
def secret_notation_command(ctx, text):
    """Get secret record via notation"""
    ctx.obj["secret"].get_via_notation(notation=text)


@click.command(
    name='update',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--uid', '-u', required=True, type=str, help="Unique identifier of record.")
@click.option('--field', type=str, multiple=True, help="Update value in field section of vault")
@click.option('--custom-field', type=str, multiple=True, help="Update value in custom field section of vault")
@click.option('--field-json', type=str, multiple=True, help="Update value in field section of vault using JSON")
@click.option('--custom-field-json', type=str, multiple=True,
              help="Update value in custom field section of vault using JSON")
@click.pass_context
def secret_update_command(ctx, uid, field, custom_field, field_json, custom_field_json):
    """Update an existing record"""
    ctx.obj["secret"].update(
        uid=uid,
        fields=field,
        custom_fields=custom_field,
        fields_json=field_json,
        custom_fields_json=custom_field_json
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
    """Download a file from a secret record"""
    ctx.obj["secret"].download(
        uid=uid,
        name=name,
        file_output=file_output,
        create_folders=create_folders
    )


@click.command(
    name='totp',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.argument('uid', type=str, nargs=1)
@click.pass_context
def secret_totp_command(ctx, uid):
    """Get TOTP code from a secret Record UID"""
    ctx.obj["secret"].get_totp_code(
        uid=uid
    )


@click.command(
    name='password',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.pass_context
@click.option('--length', '-l', required=False, type=int, default=0,
              help="Length of password. Will evenly split lowercase, uppercase, digits, and special characters.")
@click.option('-lc', required=False, type=int, default=0, help="Number of lowercase letters.")
@click.option('-uc', required=False, type=int, default=0, help="Number of uppercase letters.")
@click.option('-d', required=False, type=int, default=0, help="Number of digits.")
@click.option('-sc', required=False, type=int, default=0, help="Number of special characters.")
def secret_password_command(ctx, length, lc, uc, d, sc):
    """Generate a password"""

    # Get the total length of character groups. If the total is greater than 0,
    # then make the length the total count of the character groups.
    char_count = lc + uc + d + sc
    if char_count > 0:
        if 0 < length != char_count:
            raise KsmCliException("Both length and at least one of the character group counts has been set. "
                                  "Either set the length or the character group counts, but not both. The total count "
                                  "of the character groups counts will determine the length.")
        length = char_count

    if length == 0:
        length = 64

    ctx.obj["secret"].generate_password(
        length=length,
        lowercase=lc,
        uppercase=uc,
        digits=d,
        special_characters=sc
    )


# SECRET TEMPLATE COMMAND


@click.group(
    name='template',
    cls=AliasedGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
def secret_template_command():
    """Record and field information"""


@click.command(
    name='record',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.pass_context
@click.option('--show-list', '-l', is_flag=True, help='List available record types.')
@click.option('--output-format', '-o', type=click.Choice(['yaml', 'json'], case_sensitive=False), default='json',
              help='File format to export.')
@click.option('--output-file', '-f', type=str, help='Write template to a file.')
@click.option('--version', type=click.Choice(['v3'], case_sensitive=False), default='v3',
              help='Record version.')
@click.argument('record_type', type=str, nargs=-1)
def secret_template_record_command(ctx, show_list, output_format, output_file, version, record_type):
    """Get a record type or list available record types"""

    if show_list is True:
        print("", file=sys.stderr)
        ctx.obj["secret"].get_record_type_list(version=version)
        print("", file=sys.stderr)
    else:
        if record_type is None or len(record_type) == 0:
            raise KsmCliException("A record type is required.")

        print("", file=sys.stderr)
        ctx.obj["secret"].get_record_type_template(
            record_type=record_type[0],
            version=version,
            output_format=output_format,
            file=output_file
        )
        print("", file=sys.stderr)


@click.command(
    name='field',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.pass_context
@click.option('--show-list', '-l', is_flag=True, help='List available fields types.')
@click.option('--output-format', '-o', type=click.Choice(['yaml', 'json'], case_sensitive=False), default='json',
              help='Display field schema in this format.')
@click.option('--version', type=click.Choice(['v3'], case_sensitive=False), default='v3',
              help='Record version.')
@click.argument('field_type', type=str, nargs=-1)
def secret_template_field_command(ctx, show_list, output_format, version, field_type):
    """List field types and field schemas"""
    if show_list is True:
        print("", file=sys.stderr)
        ctx.obj["secret"].get_field_type_list(version=version)
    else:
        if field_type is None or len(field_type) == 0:
            raise KsmCliException("A field type is required.")

        print("", file=sys.stderr)
        ctx.obj["secret"].get_field_type_schema(
            field_type=field_type[0],
            output_format=output_format,
            version=version
        )
        print("", file=sys.stderr)


secret_template_command.add_command(secret_template_record_command)
secret_template_command.add_command(secret_template_field_command)


# SECRET ADD COMMAND


@click.group(
    name='add',
    cls=AliasedGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
def secret_add_command():
    """Add a secret record to a folder"""


@click.command(
    name='editor',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.pass_context
@click.option('--shared-folder-uid', '--sf', required=True, type=str, help="Place record in folder with UID.")
@click.option('--record-type', '--rt', required=True, type=str, help="Record type")
@click.option('--password-generate', '-p', is_flag=True, help='Generate passwords for empty password fields.')
@click.option('--title', '-t', type=str, help="Record title")
@click.option('--notes', '-n', type=str, help="Record simple note")
@click.option('--output-format', '-o', type=click.Choice(['yaml', 'json'], case_sensitive=False), default='json',
              help='File format to display in editor.')
@click.option('--editor', '-e', type=str, help='Application to use to edit record data.')
@click.option('--version', type=click.Choice(['v3'], case_sensitive=False), default='v3', help='Record version.')
def secret_add_editor_command(ctx, shared_folder_uid, record_type, password_generate, title, notes,
                              output_format, editor, version):
    """Add a secret record via a text editor"""

    ctx.obj["secret"].add_record_interactive(
        version=version,
        folder_uid=shared_folder_uid,
        record_type=record_type,
        output_format=output_format,
        password_generate_flag=password_generate,
        title=title,
        notes=notes,
        editor=editor
    )
    print("", file=sys.stderr)


@click.command(
    name='file',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.pass_context
@click.option('--shared-folder-uid', '--sf', required=True, type=str, help="Place record in folder with UID.")
@click.option('--file', '-f', required=True, type=str, help='Add records from record script file.')
@click.option('--password-generate', '-p', is_flag=True, help='Generate passwords for empty password fields.')
def secret_add_file_command(ctx, shared_folder_uid, file, password_generate):
    """Add a secret record(s) from a file"""

    ctx.obj["secret"].add_record_from_file(
        folder_uid=shared_folder_uid,
        file=file,
        password_generate_flag=password_generate,
    )
    print("", file=sys.stderr)


@click.command(
    name='field',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.pass_context
@click.option('--shared-folder-uid', '--sf', required=True, type=str, help="Place record in folder with UID.")
@click.option('--record-type', '--rt', required=True, type=str, help="Record type")
@click.option('--title', '-t', required=True, type=str, help="Record title")
@click.option('--password-generate', '-p', is_flag=True, help='Generate passwords for empty password fields.')
@click.option('--notes', '-n', type=str, help="Record simple note")
@click.option('--version', type=click.Choice(['v3'], case_sensitive=False), default='v3', help='Record version.')
@click.argument('field_args', type=str, nargs=-1)
def secret_add_field_command(ctx, shared_folder_uid, record_type, title, password_generate, notes, version,
                             field_args):
    """Add a secret record from a command line field arguments"""

    ctx.obj["secret"].add_record_from_field_args(
        version=version,
        folder_uid=shared_folder_uid,
        password_generate_flag=password_generate,
        record_type=record_type,
        title=title,
        notes=notes,
        field_args=list(field_args)
    )
    print("", file=sys.stderr)


secret_add_command.add_command(secret_add_field_command)
secret_add_command.add_command(secret_add_file_command)
secret_add_command.add_command(secret_add_editor_command)


secret_command.add_command(secret_list_command)
secret_command.add_command(secret_get_command)
secret_command.add_command(secret_notation_command)
secret_command.add_command(secret_update_command)
secret_command.add_command(secret_add_command)
secret_command.add_command(secret_download_command)
secret_command.add_command(secret_totp_command)
secret_command.add_command(secret_password_command)
secret_command.add_command(secret_template_command)


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
    """Wrap an application and replace env variables"""
    ex = Exec(cli=ctx.obj["cli"])
    ex.execute(cmd=cmd, capture_output=capture_output, inline=inline)


# CONFIG COMMAND
@click.group(
    name='config',
    cls=AliasedGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
@click.pass_context
def config_command(ctx):
    """Configure the command line tool"""
    ctx.obj["profile"] = Profile(cli=ctx.obj["cli"])
    pass


@click.command(
    name='show',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.pass_context
def config_show_command(ctx):
    """Show current configuration"""
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


@click.command(
    name='cache',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--enable/--disable', required=True, help="Enable or disable cache.")
@click.pass_context
def config_cache_command(ctx, enable):
    """Enable or disable record cache"""
    ctx.obj["profile"].set_cache(enable)


@click.command(
    name='record-type-dir',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--directory', "-d", type=str, help='Location of record type schema directory')
@click.option('--clear', is_flag=True, help='Clear location of record type schema directory')
@click.pass_context
def config_rt_dir_command(ctx, directory, clear):
    """Set the directory that contains record type schemas"""

    if clear is True:
        directory = None
    elif directory is None:
        raise KsmCliException("Either a --directory is required or the --clear flag set")

    ctx.obj["profile"].set_record_type_dir(directory)


@click.command(
    name='editor',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--application', "--app", type=str, help='Application path and name to use for editor.')
@click.option('--blocking', is_flag=True, help='Application requires blocking.')
@click.option('--process-name', type=str, help='Application process name.')
@click.option('--clear', is_flag=True, help='Clear location of record type schema directory')
@click.pass_context
def config_editor_command(ctx, application, blocking, process_name, clear):
    """Set the editor to use for record editing"""

    if clear is True:
        application = None
        blocking = False
        process_name = None
    if clear is not True and application is None:
        raise KsmCliException("Either a --application is required or the --clear flag set")

    ctx.obj["profile"].set_editor(editor=application, use_blocking=blocking, process_name=process_name)


config_command.add_command(config_show_command)
config_command.add_command(config_log_command)
config_command.add_command(config_cache_command)
config_command.add_command(config_rt_dir_command)
config_command.add_command(config_editor_command)


# REDEEM COMMAND
@click.group(
    name='init',
    cls=AliasedGroup,
    help_headers_color='yellow',
    help_options_color='green'
)
@click.pass_context
def init_command(ctx):
    """Initialize a configuration file for integrations"""
    ctx.obj["profile"] = Profile(cli=ctx.obj["cli"])


@click.command(
    name='k8s',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--name', '-n', type=str, help="Name of secret", default='ksm-config')
@click.option('--namespace', '--ns', type=str, help="Namespace", default='default')
@click.option('--hostname', '-h', type=str, help="Hostname of secrets manager server.")
@click.option('--apply', '-a', is_flag=True, help='Apply to k8s secrets.')
@click.option('--immutable', '-i', is_flag=True, help='Make secret immutable (Kubernetes >=v1.21)')
@click.option('--skip-ssl-verify', is_flag=True, help='Skip the SSL verify')
@click.argument('token', type=str, nargs=1)
@click.pass_context
def init_k8s_command(ctx, name, namespace, hostname, apply, immutable, skip_ssl_verify, token):
    """Output the config as a k8s secret"""
    Init(cli=ctx.obj["cli"], token=token, hostname=hostname, skip_ssl_verify=skip_ssl_verify).get_k8s(
        name=name,
        namespace=namespace,
        immutable=immutable,
        apply=apply)


# Want to use json, however click is using some reflection which is picking up the json module :/
@click.command(
    name='default',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.option('--plain', is_flag=True, help='do not Base64 encode.')
@click.option('--hostname', '-h', type=str, help="Hostname of secrets manager server.")
@click.option('--skip-ssl-verify', is_flag=True, help='Skip the SSL verify')
@click.argument('token', type=str, nargs=1)
@click.pass_context
def init_json_command(ctx, plain, hostname, skip_ssl_verify, token):
    """Output the config as base64 encoded JSON"""
    Init(cli=ctx.obj["cli"], token=token, hostname=hostname, skip_ssl_verify=skip_ssl_verify).get_json(plain)


init_command.add_command(init_json_command)
init_command.add_command(init_k8s_command)


@click.command(
    name='version',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
@click.pass_context
def version_command(ctx):
    """Get module versions and information"""

    versions = get_versions()

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

    try:
        if versions["keeper-secrets-manager-cli"] != "Unknown":
            update = update_available("keeper-secrets-manager-cli", versions)
            if update is not None:
                print("Version {} is available for the CLI".format(update.available_version))

        if versions["keeper-secrets-manager-core"] != "Unknown":
            update = update_available("keeper-secrets-manager-core", versions)
            if update is not None:
                print("Version {} is available for the SDK".format(update.available_version))
    except (Exception,) as _:
        pass


@click.command(
    name='shell',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
def shell_command():
    """Run KSM in a shell"""

    # https://manytools.org/hacker-tools/ascii-banner/
    logo = """
██╗  ██╗███████╗███╗   ███╗     ██████╗██╗     ██╗
██║ ██╔╝██╔════╝████╗ ████║    ██╔════╝██║     ██║
█████╔╝ ███████╗██╔████╔██║    ██║     ██║     ██║
██╔═██╗ ╚════██║██║╚██╔╝██║    ██║     ██║     ██║
██║  ██╗███████║██║ ╚═╝ ██║    ╚██████╗███████╗██║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝     ╚═════╝╚══════╝╚═╝                                                                          
    """
    print(Fore.BLUE + logo + Style.RESET_ALL)

    versions = get_versions()

    print(Fore.CYAN + "Current Version: " + Fore.GREEN + versions.get("keeper-secrets-manager-cli") + Style.RESET_ALL)
    update = update_available("keeper-secrets-manager-cli", versions)
    if update is not None:
        print(Fore.YELLOW + "Version {} is available.".format(update.available_version) + Style.RESET_ALL)

    print("\nRunning in shell mode. Type 'quit' to exit.\n")

    KsmCliException.in_a_shell = True
    repl(click.get_current_context(), prompt_kwargs={
        "message": u'KSM Shell (? for help) > '
    })


@click.command(
    name='quit',
    cls=HelpColorsCommand,
    help_options_color='blue'
)
def quit_command():
    """Quit shell mode"""
    repl_exit()


# TOP LEVEL COMMANDS
cli.add_command(profile_command)
cli.add_command(secret_command)
cli.add_command(exec_command)
cli.add_command(config_command)
cli.add_command(init_command)
cli.add_command(version_command)
cli.add_command(shell_command)
cli.add_command(quit_command)


def main():
    try:
        # This init colors for Windows. CMD looks great. PS has no yellow :(
        init()

        program_name = "ksm"
        # If we are running in the shell mode, there is no program name for the usage. Blank it out.
        if "shell" in sys.argv:
            program_name = ""

        cli(obj={"cli": None}, prog_name=program_name)
    except Exception as err:
        # Set KSM_DEBUG to get a stack trace. Secret env var.
        if os.environ.get("KSM_DEBUG") is not None:
            print(traceback.format_exc(), file=sys.stderr)
        sys.exit("ksm had a problem: {}".format(err))


if __name__ == '__main__':
    main()
