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

import os
import shutil
import platform
import subprocess
import time
import psutil


def find_ksm_path(find_path, is_file=True):

    # Directories to scan for the keeper INI file, covering Linux and Windows paths.
    # Entries that contain None (from an unset env var) are skipped entirely so
    # find_ksm_path never probes a relative path built from a missing variable.
    dir_locations = [
        [os.environ.get("KSM_INI_DIR")],
        [os.getcwd()],

        # Linux / macOS
        [os.environ.get("HOME")],
        [os.environ.get("HOME"), ".config", "ksm"],
        [os.environ.get("HOME"), ".keeper"],
        ["/etc"],
        ["/etc", "ksm"],
        ["/etc", "keeper"],

        # Windows
        [os.environ.get("USERPROFILE")],
        [os.environ.get("APPDATA"), "Keeper"],
        [os.environ.get("PROGRAMDATA"), "Keeper"],
        [os.environ.get("PROGRAMFILES"), "Keeper"],
    ]

    for dir_location in dir_locations:
        if any(part is None for part in dir_location):
            continue
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
