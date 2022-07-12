# -*- coding: utf-8 -*-

from keeper_secrets_manager_helper.v3.field_type import FieldType, get_field_type_map
from keeper_secrets_manager_helper.v3.enum import BaseEnum
from keeper_secrets_manager_helper.common import load_file
import os
import yaml
import json
import re


# Make a base class for all our record types
class RecordType:

    def __init__(self):
        self.field_type_map = get_field_type_map()

    # self.schema and self.name works, however the dynamic class generation will add it. To make PyCharm happy,
    # get the schema and name using getattr.

    def get_schema(self):
        return getattr(self, "schema")

    def get_name(self):
        return getattr(self, "name")

    def get_standard_fields(self):
        return self.get_schema().get("fields", [])

    def get_custom_fields(self):
        return self.get_schema().get("custom_fields", [])

    def _expand_value_type(self, schema, allow_multiple=None, is_required=False):

        value_type = schema.get("value_type")
        # If the record doesn't set allow_multiple to True/False, allow the field to set the value.
        if allow_multiple is None:
            allow_multiple = schema.get("allow_multiple", False)
        if issubclass(value_type, FieldType) is True:
            new_schema = value_type.schema
            return self._expand_value_type(new_schema, is_required=is_required)
        elif issubclass(value_type, BaseEnum) is True:
            value = "<#ADD: " + value_type.build_example() + ">"
            return value
        elif issubclass(value_type, dict):
            value_block = {}
            for key, info in schema.get("schema").items():
                value_block[key] = self._expand_value_type(info, is_required=is_required)
            return value_block
        else:
            value = "<#ADD: " + schema.get("desc", "Insert a {}".format(value_type.__name__)) + ">"
            if allow_multiple is True:
                value = [value]
            return value

    def generate_template_dict(self, title=None, notes=None):
        fields = []

        for field in self.get_schema().get("fields"):

            field_type = field.get("type")

            data = {
                "type": field_type
            }

            if field_type not in self.field_type_map:
                raise ValueError("Field type '{}' does not exists.".format(field_type))
            field_type_obj = self.field_type_map[field_type]
            field_schema = field_type_obj.schema
            data["value"] = self._expand_value_type(field_schema,
                                                    allow_multiple=field.get("allow_multiple", None),
                                                    is_required=field.get("required", False))
            data["privacyScreen"] = field_schema.get("privacy_screen", False)
            field_type_obj.add_template_specifics(data)
            fields.append(data)

        template = {
            "version": "v3",
            "kind": "KeeperRecord",
            "data": [{
                "recordType": self.get_name(),
                "title": title if title is not None else "<#ADD: The title of record here. This is required.>",
                "notes": notes if notes is not None else "<#ADD: Add some notes or remove.>",
                "fields": fields,
            }]
        }

        return template

    @staticmethod
    def generate_yaml_template(template_dict):
        return yaml.dump(template_dict, sort_keys=False)

    @staticmethod
    def generate_json_template(template_dict):
        return json.dumps(template_dict, indent=4, sort_keys=False)

    def generate_template(self, output_format, title=None, notes=None):
        template_dict = self.generate_template_dict(title=title, notes=notes)
        if output_format == "json":
            return self.generate_json_template(template_dict)
        return self.generate_yaml_template(template_dict)


# This maps a record type/name to a type class
class_map_by_type = {}


def load_record_type_from_file(file):
    load_record_type_from_data(load_file(file))


def load_record_type_from_data(record_types):

    for item in record_types.get("data", []):

        # Make sure we haven't loaded this class already. Cannot overwrite classes.
        if item.get("name") in class_map_by_type:
            raise ValueError("Cannot overwrite class {}".format(item.get("class")))
        record_type_class = type(item.get("class"), (RecordType,), {
            "name": item.get("name"),
            "schema": {
                "fields": item.get("fields", [])
            }
        })
        globals()[record_type_class.__name__] = record_type_class
        class_map_by_type[item.get("name")] = record_type_class


default_record_type_file = "default_record_types.yml"

# Get the directory of the executable file. If last directory is keeper_secrets_manager_cli, get the parent
# directory. There is no keeper_secrets_manager_cli directory.

# This is the Pypi module installed check. The default_record_type_file.yml will be in this directory along
# the other V3 modules.
current_directory = os.path.dirname(__file__)
schema_dir = None
if os.path.exists(os.path.join(current_directory, default_record_type_file)) is True:
    schema_dir = current_directory

# Else this is the binary install. For PyInstaller, we move the YAML file to the rood
# directory of the application. We don't want to hardcode the directory, so walk backwards
# from here looking for the file. If we get to the root directory the file wasn't found.
else:
    # Change the filename to include the version
    default_record_type_file = f"v3_{default_record_type_file}"

    # Find the default_record_type_file in the path. Quit if reach the root directory.
    root_dir = os.path.abspath(os.sep)
    while current_directory != root_dir:
        current_directory = os.path.dirname(current_directory)
        if os.path.exists(os.path.join(current_directory, default_record_type_file)) is True:
            schema_dir = current_directory
            break
    if schema_dir is None:
        raise FileNotFoundError(f"Cannot find {default_record_type_file} in the binary app.")

load_record_type_from_file(os.path.join(schema_dir, default_record_type_file))


def get_class_by_type(class_name):
    if class_name in class_map_by_type:
        return class_map_by_type[class_name]
    raise ImportError("Record type class {} is not loaded.".format(class_name))


def get_record_type_list():
    return class_map_by_type.keys()


def make_class_name(name):
    name = name.lower()
    name = re.sub(r'[^a-zA-Z0-9\s]', '', name)
    name_parts = re.split(' +', name)
    name = ""
    for item in name_parts:
        if item is None or item == "":
            continue
        name += item[0].upper() + item[1:]
    return name


def camel_case_split(value):
    matches = re.finditer('.+?(?:(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|$)', value)
    return "_".join([m.group(0) for m in matches]).lower()


def load_commander_record_type_from_file(file):
    load_commander_record_type_from_data(load_file(file))


def load_commander_record_type_from_data(data):

    if isinstance(data, dict) is True:
        data = [data]

    record_schema = {
        "data": []
    }

    index = 0
    for item in data:
        if item.get("recordTypeId") is None:
            raise ValueError(f"Missing recordTypeId for record index {index}. Is this an export of a Keeper "
                             f"Commander record type information.")
        if item.get("content") is None:
            raise ValueError(f"Missing content for record index {index}. Is this an export of a Keeper "
                             f"Commander record type information.")

        content = json.loads(item.get("content"))

        name = content.get('$id')
        class_name = make_class_name(name)

        record_data = {
            "class": class_name,
            "name": name,
            "fields": []
        }

        for field in content.get("fields"):
            field_data = {
                "type": field.get("$ref")
            }
            for param in ["label", "required", "privacyScreen", "enforceGeneration", "privacyScreen", "complexity"]:
                value = field.get(param)
                if value is not None:
                    field_data[camel_case_split(param)] = value

            record_data["fields"].append(field_data)

        record_schema["data"].append(record_data)

    load_record_type_from_data(record_schema)
