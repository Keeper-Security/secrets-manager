# -*- coding: utf-8 -*-

from importlib import import_module


class FieldType:

    default_version = "v3"

    @staticmethod
    def get_field_type_list(version=None):
        if version is None:
            version = FieldType.default_version
        mod = import_module(f"keeper_secrets_manager_helper.{version}.field_type")
        return getattr(mod, "get_field_type_list")()

    @staticmethod
    def get_field_type_schema(field_type, version=None):
        if version is None:
            version = FieldType.default_version
        mod = import_module(f"keeper_secrets_manager_helper.{version}.field_type")
        return getattr(mod, "get_field_type_schema")(field_type)
