import os
import shutil
import platform
import subprocess


def find_ksm_path(find_path, is_file=True):

    # Directories to scan for the keeper INI file. This both Linux and Windows paths. The os.path.join
    # should create a path that the OS understands. The not_set stuff in case the environmental var is not set.
    # The last entry is the current working directory.
    not_set = "_NOTSET_"
    dir_locations = [
        [os.environ.get("KSM_INI_DIR", not_set)],
        [os.getcwd()],

        # Linux
        [os.environ.get("HOME", not_set)],

        # This seems like where other applications like to store their configs.
        [os.environ.get("HOME", not_set), ".config", "ksm"],

        [os.environ.get("HOME", not_set), ".keeper"],
        ["/etc"],
        ["/etc", "ksm"],
        ["/etc", "keeper"],

        # Windows
        [os.environ.get("USERPROFILE", not_set)],
        [os.environ.get("APPDIR", not_set)],
        [os.environ.get("PROGRAMDATA", not_set), "Keeper"],
        [os.environ.get("PROGRAMFILES", not_set), "Keeper"],
    ]

    for dir_location in dir_locations:
        path = os.path.join(*dir_location, find_path)
        if (is_file is True and os.path.exists(path) and os.path.isfile(path)) or os.path.exists(path):
            return path

    return None


def launch_editor(file, editor=None, macos_ui=False):

    if editor is None:

        editor = os.environ.get("EDITOR")
        if editor is None:
            # If no editor is try to find one.
            if platform.system() == "Windows":
                # If someone installed Visual Code, use that first. It had a nice JSON and YAML syntax tester. Else
                # call back to good old notepad
                editor_list = ["code.cmd", "notepad.exe"]
            else:
                # Why this order. No one installs emacs unless they want it. Nano is the most "friendly" for people
                # and it normally the default. vim and vi for back up.
                editor_list = ["emacs", "nano", "vim", "vi"]
            for editor_file in editor_list:
                located = shutil.which(editor_file)
                if located is not None:
                    editor = located
                    break
            if editor is None:
                raise FileNotFoundError("Cannot find an editor. Please configure an editor in the CLI or set the "
                                        "environmental variable 'EDITOR' with the name, and path if required, of a "
                                        "text editor.")

    cmd = [editor, file]

    # If using an MacOS editor that has a UI. You have to use 'open' to launch the editor, the -W will block
    # until the application is closed ( not the windows is closed, then entire application is closed).
    if macos_ui is True and platform.system() == "Darwin":
        cmd = ["open", "-W", "-a"] + cmd

    exit_code = subprocess.call(cmd)
    if exit_code == 1:
        pass
