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

import sys
from keeper_secrets_manager_core.mock import MockConfig


if __name__ == "__main__":
    args = sys.argv[1:]

    if args[0] == "get":
        config = MockConfig().make_base64()
        print(config)

    exit(0)
