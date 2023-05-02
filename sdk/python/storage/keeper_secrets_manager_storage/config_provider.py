# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2023 Keeper Security Inc.
# Contact: sm@keepersecurity.com
"""This module provides low-level interface for working with KSM configurations
stored in remote locations like AWS/Azure/GCP secret, etc.
"""
from abc import ABC, abstractmethod


class IConfigProvider(ABC):
    """ Interface for the config provider """

    @abstractmethod
    def read_config(self) -> str:
        """ Read configuration string from storage """
        return ""

    @abstractmethod
    def write_config(self, config: str) -> str:
        """ Write configuration string to storage """
        del config
        return ""
