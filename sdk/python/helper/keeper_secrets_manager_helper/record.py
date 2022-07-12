# -*- coding: utf-8 -*-

from .common import load_file
from importlib import import_module


class Record:

    @staticmethod
    def create_from_file(file, password_generate=False):
        record_data = load_file(file)

        if record_data.get("kind") != "KeeperRecord":
            raise ValueError(".kind is not 'KeeperRecord'")

        version = record_data.get("version")
        if version is None or version == "":
            raise ValueError(".version is missing or blank")

        mod = import_module(f"keeper_secrets_manager_helper.{version}.record")
        return getattr(mod, "Record").create_from_data(record_data, password_generate=password_generate)

    def __init__(self, version):

        self.version = version

        try:
            self.record_mod = import_module(f"keeper_secrets_manager_helper.{self.version}.record")
            self.parser_mod = import_module(f"keeper_secrets_manager_helper.{self.version}.parser")
            self.record_type_mod = import_module(f"keeper_secrets_manager_helper.{self.version}.record_type")
        except ImportError as err:
            raise Exception(f"Version {self.version} is not supported: " + str(err))

    def create_from_field_list(self, record_type, fields, title=None, notes=None,
                               password_generate=None, password_complexity=None):
        return [getattr(self.record_mod, "Record")(
            record_type=record_type,
            title=title,
            notes=notes,
            fields=fields,
            password_generate=password_generate,
            password_complexity=password_complexity
        )]

    def create_from_field_args(self, **kwargs):
        kwargs["fields"] = getattr(self.parser_mod, "Parser")().parse_field(kwargs.get("field_args"))
        return [getattr(self.record_mod, "Record")(**kwargs)]

    def get_template(self, record_type, output_format, title=None, notes=None):
        get_class_by_type = getattr(self.record_type_mod, "get_class_by_type")
        record_type = get_class_by_type(record_type)()
        return record_type.generate_template(output_format=output_format, title=title, notes=notes)

    def get_template_list(self):
        return getattr(self.record_type_mod, "get_record_type_list")()
