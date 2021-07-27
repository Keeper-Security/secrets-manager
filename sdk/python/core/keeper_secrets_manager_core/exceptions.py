#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com

class KeeperError(Exception):

    def __init__(self, message):

        self.message = message

        super().__init__(self.message)


class KeeperAccessDenied(Exception):

    def __init__(self, message):

        self.message = message

        super().__init__(self.message)
