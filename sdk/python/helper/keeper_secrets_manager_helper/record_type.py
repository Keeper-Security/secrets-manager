# -*- coding: utf-8 -*-

from .common import load_file
from importlib import import_module
import os
import re


class RecordType:

    default_version = "v3"

    @staticmethod
    def load_record_types(file, version=None):
        data = load_file(file)

        data_test = data
        if isinstance(data, list) is True:
            data_test = data[0]

        # Check if a structured file
        if data_test.get("kind") is not None:
            return RecordType.load_helper_record_types(data)
        else:
            if data_test.get("recordTypeId") is not None:
                return RecordType.load_commander_record_types(data, version)
            else:
                raise Exception("Cannot determine the type of record type file.")

    @staticmethod
    def load_helper_record_types(data):
        version = data.get("version")
        mod = import_module(f"keeper_secrets_manager_helper.{version}.record_type")
        return getattr(mod, "load_record_type_from_data")(data)

    @staticmethod
    def load_commander_record_types(data, version=None):
        if version is None:
            version = RecordType.default_version
        mod = import_module(f"keeper_secrets_manager_helper.{version}.record_type")
        return getattr(mod, "load_commander_record_type_from_data")(data)

    @staticmethod
    def find_and_load_record_type_schema_files(path):

        for root, dirs, files in os.walk(path):
            for file in files:
                if re.search("(json|ya*ml)$", file, re.IGNORECASE) is not None:
                    try:
                        RecordType.load_record_types(os.path.join(root, file))
                    except (Exception,):
                        pass

    @staticmethod
    def get_record_type_list(version=None):
        if version is None:
            version = RecordType.default_version
        mod = import_module(f"keeper_secrets_manager_helper.{version}.record_type")
        return getattr(mod, "get_record_type_list")()
