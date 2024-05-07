# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2024 Keeper Security Inc.
# Contact: sm@keepersecurity.com
#

import json
import sys
from typing import List, Tuple
from colorama import Fore, Style
from keeper_secrets_manager_core.core import CreateOptions, KeeperFolder
from keeper_secrets_manager_cli.exception import KsmCliException
from .table import Table


class Folder:
    """ Provides full folder CRUD support """
    def __init__(self, cli):
        self.cli = cli

    @staticmethod
    def _color_it(value, color=Style.RESET_ALL, use_color=True):
        if use_color is True:
            value = color + value + Style.RESET_ALL
        return value

    @staticmethod
    def get_subfolders(folder: str, folders: list):
        """ Retrieve a list of sub-folder UIDs recursively """
        if not folder:  # root folder - return all UIDs
            return set([x.folder_uid for x in folders])

        subtree = set()
        for f in folders:
            if f.folder_uid == folder:
                subtree.add(folder)
                continue
            branch = set([f.folder_uid])
            parent_folder = next((x for x in folders if x.folder_uid == f.parent_uid), None)
            while parent_folder and parent_folder.folder_uid != folder:
                branch.add(parent_folder.folder_uid)
                parent_folder = next((x for x in folders if x.folder_uid == parent_folder.parent_uid), None)
            if parent_folder and parent_folder.folder_uid == folder:
                branch.add(folder)
            if folder in branch:
                subtree = subtree.union(branch)
        return subtree

    def list_folders(self, folder: str = "",
                    recursive: bool = False,
                    list_records: bool = False,
                    output_format: str = "json",
                    use_color=None):
        """ List folders """

        if use_color is None:
            use_color = self.cli.use_color

        try:
            items = []
            folders = self.cli.client.get_folders()

            if folder:  # filter folders
                if recursive:
                    flst = Folder.get_subfolders(folder, folders)
                    folders = [x for x in folders if x.folder_uid in flst]
                else:  # non recursive - get current folder only (if present)
                    folders = [x for x in folders if x.folder_uid == folder]

            records = []
            if list_records:
                resp = self.cli.client.get_secrets(full_response=True)
                records = resp.records
                if not folder:  # add standalone records - direct share
                    standalone = [x for x in records
                                  if not x.inner_folder_uid
                                  and not x.folder_uid]
                    items.extend([{"type": "rec",
                                   "parent_uid": "",
                                   "uid": x.uid,
                                   "title": x.title}
                                 for x in standalone])

            for fldr in folders:  # Left join to show empty folders
                items.append({"type": "dir",
                              "parent_uid": fldr.parent_uid,
                              "uid": fldr.folder_uid,
                              "title": fldr.name})
                items.extend([{"type": " rec",
                               "parent_uid": fldr.folder_uid,
                               "uid": x.uid,
                               "title": x.title}
                             for x in records
                             if ((x.inner_folder_uid == fldr.folder_uid) or
                                 (not x.inner_folder_uid and
                                  x.folder_uid == fldr.folder_uid))
                              ])

            if output_format == 'json':
                self.cli.output(json.dumps(items, indent=4))
            else:  # output_format == 'text'
                table = Table(use_color=use_color)
                table.add_column("Type", data_color=Fore.GREEN)
                table.add_column("Parent", data_color=Fore.YELLOW)
                table.add_column("UID", data_color=Fore.YELLOW)
                table.add_column("Title", data_color=Fore.GREEN, allow_wrap=True)
                for x in items:
                    table.add_row([x["type"], x["parent_uid"], x["uid"], x["title"]])
                self.cli.output(f"\n{table.get_string()}\n")
        except Exception as err:
            raise KsmCliException(f"Error loading folders: {str(err)}")

    def add_folder(self, parent_folder: str = "", title: str = ""):
        """ Create new folder """
        self._check_if_can_add_folders()

        try:
            folder_options, folders = self.build_folder_options(parent_folder)
            folder_uid = self.cli.client.create_folder(folder_options, title, folders)
        except Exception as err:
            raise KsmCliException(f"{err}")

        print("The following is the new folder UID ...", file=sys.stderr)
        return self.cli.output(folder_uid)

    def update_folder(self, folder_uid: str = "", folder_name: str = ""):
        """ Rename folder """
        try:
            self.cli.client.update_folder(folder_uid, folder_name)
        except Exception as err:
            raise KsmCliException(f"Could not update folder UID: {folder_uid} - Error: {err}")

    def delete_folders(self, uids: List[str] = [], force: bool = False, output_format: str = "text", use_color=None):
        """ Delete folders """
        if use_color is None:
            use_color = self.cli.use_color
        try:
            resp = self.cli.client.delete_folder(folder_uids=uids, force_deletion=force)
            output = [{"uid": x.get("folderUid", ""),
                       "responseCode": x.get("responseCode", ""),
                       "error": x.get("errorMessage", "")}
                      for x in resp if x.get("folderUid", "") in uids]
            output.extend([{"uid": u, "responseCode": "n/a", "error": "Not found"}
                           for u in uids
                           if next((r for r in resp if r.get("folderUid") == u), None) is None])
            if output_format == 'json':
                self.cli.output(json.dumps(output, indent=4))
            else:  # output_format == 'text'
                table = Table(use_color=use_color)
                table.add_column("UID", data_color=Fore.GREEN)
                table.add_column("Response Code", data_color=Fore.YELLOW)
                table.add_column("Error", data_color=Fore.RED, allow_wrap=True)
                for x in output:
                    table.add_row([x["uid"], x["responseCode"], x["error"]])
                self.cli.output(f"\n{table.get_string()}\n")
        except Exception as err:
            raise KsmCliException(f"Could not delete folders: {err}")

    def _check_if_can_add_folders(self):
        # Check to see if appOwnerPublicKey is in the keeper.ini.
        # It's a newly added key and if the profile is too old
        # we can't add or update a folders.
        profile_config = self.cli.profile.get_profile_config(self.cli.profile.get_active_profile_name())
        if profile_config.app_owner_public_key is None:
            raise KsmCliException("Your profile is out of date. It is missing the application order key. "
                                  "To create a record you will need to init a profile with a new token.")

    def build_folder_options(self, folder_uid: str, folders: List[KeeperFolder] = []) -> Tuple[CreateOptions, List[KeeperFolder]]:
        """ Build and return folder create options and folders list """

        # find closest shared folder parent
        if not folders:
            folders = self.cli.client.get_folders() or []

        shared_folder = next((x for x in folders if x.folder_uid == folder_uid), None)
        while shared_folder and shared_folder.parent_uid:
            shared_folder = next((x for x in folders if x.folder_uid == shared_folder.parent_uid), shared_folder)

        if shared_folder is None:
            raise KsmCliException(f'Unable to find the shared folder for {folder_uid}')
        if not shared_folder.folder_key:
            raise KsmCliException(f'Unable to find folder key for folder {shared_folder.folder_uid}')

        # create folder options
        create_options = CreateOptions(shared_folder.folder_uid, folder_uid)
        return create_options, folders
