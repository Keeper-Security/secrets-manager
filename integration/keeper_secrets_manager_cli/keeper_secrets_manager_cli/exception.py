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

import click
from colorama import Fore, Style


class KsmCliException(click.ClickException):

    in_a_shell = False

    def colorize(self):
        if KsmCliException.in_a_shell is False:
            return str(self.message)
        else:
            return Fore.RED + str(self.message) + Style.RESET_ALL

    def format_message(self):
        return self.colorize()

    def __str__(self):
        return self.colorize()


class KsmCliIntegrityException(KsmCliException):
    """Raised when a Keychain/keyring entry fails SHA-256 integrity verification.

    This indicates the stored config was modified outside of the CLI
    (e.g., via Keychain Access.app or the ``security`` CLI).  The caller
    should surface a recovery hint directing the user to
    ``ksm profile delete`` and re-initialize.
    """


class KsmRecordSyntaxException:
    pass
