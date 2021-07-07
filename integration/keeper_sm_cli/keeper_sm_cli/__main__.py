import click
from . import KeeperCli
from .exec import Exec
from .secret import Secret
from .profile import Profile
import sys
import os
import keepercommandersm
from importlib.metadata import version as meta_version


def _get_cli(ini_file=None, profile_name=None, output=None):
    return KeeperCli(
        ini_file=ini_file,
        profile_name=profile_name,
        output=output
    )


# MAIN GROUP
@click.group()
@click.option('--ini-file', type=str, help="INI config file.")
@click.option('--profile-name', '-p', type=str, help='Config profile')
@click.option('--output', '-o', type=str, help='Output [stdout|stderr|filename]', default='stdout')
@click.pass_context
def cli(ctx, ini_file, profile_name, output):

    try:
        ctx.obj = {
            "cli": _get_cli(ini_file=ini_file, profile_name=profile_name, output=output),
            "ini_file": ini_file,
            "profile_name": profile_name,
            "output": output
        }
    except FileNotFoundError as _:
        exit("Could not find the INI file specified on the top level command. If you are running the init"
             " sub-command, specify the INI file on the sub-command parameters instead on the top level command.")
    except Exception as err:
        exit("Could not run the command. Got the error: {}".format(err))


# PROFILE GROUP


@click.group(name='profile')
def profile_command():
    """Commands for profile management."""
    pass


@click.command(name='init')
@click.option('--client-key', '-c', type=str, required=True, help="The client key.")
@click.option('--server', '-s', type=str, default="US", help="Server code or URL.")
@click.option('--ini-file', type=str, help="INI config file to create.")
@click.option('--profile-name', '-p', type=str, help='Config profile to create.')
@click.pass_context
def profile_init_command(ctx, client_key, server, ini_file, profile_name):
    """Initialize a profile."""

    # Since the top level commands are available for all command, it might be confusing the init command since
    # it take
    if ctx.obj["ini_file"] is not None and ini_file is not None:
        print("NOTE: The INI file config was set on the top level command and also set on the init sub-command. The top"
              " level command parameter will be ignored for the init sub-command.", file=sys.stderr)

    Profile.init(
        client_key=client_key,
        server=server,
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


profile_command.add_command(profile_init_command)
profile_command.add_command(profile_list_command)
profile_command.add_command(profile_active_command)

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
        force_array=force_array
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
@click.argument('cmd', type=str, nargs=-1)
@click.pass_context
def exec_command(ctx, capture_output, cmd):
    """Wrap an application and expose secrets in environmental variables."""
    ex = Exec(cli=ctx.obj["cli"])
    ex.env_replace()
    ex.execute(cmd=cmd, capture_output=capture_output)


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
    print("Python Version: {}".format(".".join([
        str(sys.version_info.major),
        str(sys.version_info.minor),
        str(sys.version_info.micro)
    ])))
    print("Python Install: {}".format(sys.executable))
    print("CLI Version: {}".format(meta_version('keeper_sm_cli')))
    print("CLI Install: {}".format(os.path.dirname(os.path.realpath(__file__))))
    print("SDK Version: {}".format(meta_version('keepercommandersm')))
    print("SDK Install: {}".format(os.path.dirname(os.path.realpath(keepercommandersm.__file__))))
    print("Config file: {}".format(ctx.obj["cli"].profile.ini_file))


# TOP LEVEL COMMANDS
cli.add_command(profile_command)
cli.add_command(secret_command)
cli.add_command(exec_command)
cli.add_command(config_command)
cli.add_command(version_command)


def main():
    cli(obj={"cli": None})


if __name__ == '__main__':
    main()
