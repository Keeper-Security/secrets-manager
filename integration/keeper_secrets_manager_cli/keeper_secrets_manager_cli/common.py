import os
import shutil
import platform
import subprocess
import time
import psutil


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


def launch_editor(file, editor=None, use_blocking=False, process_name=None):

    if editor is None:

        editor = os.environ.get("EDITOR")
        if editor is None:
            # If no editor is try to find one.
            if platform.system() == "Windows":
                # If someone installed Visual Code, use that first. It had a nice JSON and YAML syntax tester. Else
                # call back to good old notepad
                editor_list = [
                    {"cmd": "code.cmd", "use_blocking": True, "process_name": "code.exe"},
                    {"cmd": "notepad.exe"}
                ]
            else:
                # MacOS and Linux use the same list. nano is the default command line editor for both MacOS and Linux.
                editor_list = [
                    {"cmd": "nano"},
                    {"cmd": "vim"},
                    {"cmd": "vi"},
                    {"cmd": "emacs"}
                ]
            for editor_file in editor_list:
                located = shutil.which(editor_file.get("cmd"))
                if located is not None:
                    editor = located
                    use_blocking = editor_file.get("use_blocking")
                    process_name = editor_file.get("process_name",  editor_file.get("cmd"))
                    break
            if editor is None:
                raise FileNotFoundError("Cannot find an editor. Please configure an editor in the CLI or set the "
                                        "environmental variable 'EDITOR' with the name, and path if required, of a "
                                        "text editor.")

    cmd = [editor, file]

    # Windows and MacOS may launch an application that doesn't block until the application exists. Or the application
    # launches another application and exists. If we are using blocking we are going to either cause blocking on
    # the way we launch the application (MacOS) or monitor the processes until the application exits.
    if use_blocking is True:
        # In MacOS, opening the application with -W will wait until the application exits before continuing. The
        # application needs to completely exit to continue. I mean completely exit, not just that windows closed.
        if platform.system() == "Darwin":
            cmd = ["open", "-W", "-a"] + cmd
            subprocess.call(cmd)

        # Check the task list to see if the application is running. Once it is not, break out the while loop.
        elif platform.system() == "Windows":
            subprocess.call(cmd)

            while True:
                time.sleep(2)
                process_found = False
                for proc in psutil.process_iter():
                    if proc.name().lower() in process_name.lower() and proc.status() == psutil.STATUS_RUNNING:
                        process_found = True
                        break
                if process_found is False:
                    break
    else:
        subprocess.call(cmd)
