# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import json
import yaml
import os
import re
from jsonpath_rw_ext import parse
import sys
from colorama import Fore, Style
from keeper_secrets_manager_cli.exception import KsmCliException
from keeper_secrets_manager_cli.common import launch_editor
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.utils import get_totp_code, generate_password as sdk_generate_password
from keeper_secrets_manager_helper.record import Record
from keeper_secrets_manager_helper.field_type import FieldType
from keeper_secrets_manager_helper.exception import FileSyntaxException
from .table import Table, ColumnAlign
import uuid
import tempfile


class Secret:
    # Maps the type in a field to what it should pull in from the real record. There
    # might be multiple field that need to be pulled in.
    support_ref_types = {
        "addressRef": ["address"],
        "cardRef": ["paymentCard", "text", "pinCode", "addressRef"]
    }
    redact_str = "****"
    redact_placeholder = "___" + str(uuid.uuid4()) + "___"
    redact_type_list = [
        'password',
        'secret',
        'pinCode',
        'securityQuestion',
        'oneTimeCode',
        'cardRef'
    ]

    def __init__(self, cli):
        self.cli = cli

    @staticmethod
    def _should_mask(field_dict):
        return field_dict.get("type") in Secret.redact_type_list

    @staticmethod
    def _redact_value(value, use_color=True):
        if type(value) is dict:
            for key in value:
                value[key] = Secret._redact_value(value[key], use_color)
        elif type(value) is list:
            new_list = []
            for item in value:
                new_list.append(Secret._redact_value(item, use_color))
            value = new_list
        else:
            # If we are using color we want to use a unique a placeholder to replace after
            # we have a string for the entire value.
            if use_color is True:
                value = Secret.redact_placeholder
            else:
                value = Secret.redact_str
        return value

    def _field_replacement(self, fields, unmask, use_color, append_func, inflate):

        for field in fields:

            # If this is a maskable field and we are not going to unmask there is no need to load in the
            # reference value.
            if unmask is False and Secret._should_mask(field):
                continue

            # If want to inflate references and the type of the field is a supported reference type then get
            # the real record
            if inflate is True:
                field_type = field.get("type")
                if field_type in Secret.support_ref_types:
                    field["value"] = self.cli.client.inflate_field_value(field.get("value"),
                                                                         SecretsManager.inflate_ref_types[field_type])

        replace_fields = []
        for field in fields:
            value = field.get("value")

            # Should we mask the values?
            if unmask is False and Secret._should_mask(field):
                value = Secret._redact_value(value, use_color)

            append_func(field, value, replace_fields)

        return replace_fields

    def _get_standard_fields(self, raw_standard_fields, unmask, use_color, inflate):

        def _appender(field, value, fields):
            fields.append({
                "label": field.get("label", field.get("type")),
                "type": field.get("type"),
                "value": value
            })

        standard_fields = self._field_replacement(raw_standard_fields,
                                                  unmask=unmask, use_color=use_color, inflate=inflate,
                                                  append_func=_appender)

        return standard_fields

    def _get_custom_fields(self, raw_custom_fields, unmask, use_color, inflate):

        def _appender(field, value, fields):
            fields.append({
                "label": field.get("label", field.get("type")),
                "type": field.get("type"),
                "value": value
            })

        custom_fields = self._field_replacement(raw_custom_fields,
                                                unmask=unmask, use_color=use_color, inflate=inflate,
                                                append_func=_appender)

        return custom_fields

    def _record_to_dict(self, record, load_references=False, unmask=False, use_color=True, inflate=True):

        standard_fields = []
        custom_fields = []

        raw_standard_fields = record.dict.get('fields', [])
        raw_custom_fields = record.dict.get('custom', [])

        # If we have  fields check in any have references that can replace with actual values
        if len(raw_standard_fields) > 0 and load_references is True:
            standard_fields = self._get_standard_fields(raw_standard_fields, unmask, use_color, inflate)
        if len(raw_custom_fields) > 0 and load_references is True:
            custom_fields = self._get_custom_fields(raw_custom_fields, unmask, use_color, inflate)

        ret = {
            "uid": record.uid,
            "title": record.title,
            "type": record.type,
            "fields": standard_fields,
            "custom_fields": custom_fields,
            "files": [{
                "name": x.name,
                "title": x.title,
                "type": x.type,
                "last_modified": x.last_modified,
                "size": x.size
            } for x in record.files]
        }

        return ret

    @staticmethod
    def _color_it(value, color=Style.RESET_ALL, use_color=True):
        if use_color is True:
            value = color + value + Style.RESET_ALL
        return value

    @staticmethod
    def _replace_redact_placeholder(value, use_color=True, reset_color=Style.RESET_ALL):
        redact_str = Secret.redact_str
        if use_color is True:
            redact_str = Fore.RED + redact_str + reset_color
        return value.replace(Secret.redact_placeholder, redact_str)

    @staticmethod
    def _format_record(record_dict, use_color=True):
        ret = "\n"
        ret += " Record: {}\n".format(Secret._color_it(record_dict["uid"], Fore.YELLOW, use_color))
        ret += " Title: {}\n".format(Secret._color_it(record_dict["title"], Fore.YELLOW, use_color))
        ret += " Record Type: {}\n".format(Secret._color_it(record_dict["type"], Fore.YELLOW, use_color))
        ret += "\n"

        table = Table(use_color=use_color)
        table.add_column("Field", data_color=Fore.GREEN)
        table.add_column("Value", data_color=Fore.YELLOW, allow_wrap=True)
        for field in record_dict["fields"]:
            value = field["value"]
            if len(value) == 0:
                value = ""
            elif len(value) > 1 or type(value[0]) is not str:
                value = json.dumps(value)
            else:
                value = value[0]
                value = value.replace('\n', '\\n')

            value = Secret._replace_redact_placeholder(value, use_color=use_color, reset_color=Fore.YELLOW)

            # Don't show blank value pairs
            if value == "":
                continue

            label = field.get("label", field.get("type"))
            table.add_row([label, value])
        ret += table.get_string() + "\n"

        if len(record_dict["custom_fields"]) > 0:
            ret += "\n"
            table = Table(use_color=use_color)
            table.add_column("Custom Field", data_color=Fore.GREEN)
            table.add_column("Type")
            table.add_column("Value", data_color=Fore.YELLOW, allow_wrap=True)

            problems = []
            seen = {}
            for field in record_dict["custom_fields"]:
                value = field["value"]
                if len(value) == 0:
                    value = ""
                elif len(value) > 1 or type(value[0]) is not str:
                    value = json.dumps(value)
                else:
                    value = value[0]
                    value = value.replace('\n', '\\n')

                # Don't show blank value pairs
                if value == "":
                    continue

                value = Secret._replace_redact_placeholder(value, use_color=use_color, reset_color=Fore.YELLOW)

                label = field["label"]
                if field["label"] in seen:
                    problems.append(field["label"])
                    label += " (!!)"
                seen[field["label"]] = True

                table.add_row([label, field["type"], value])

            ret += table.get_string() + "\n"
            if len(problems) > 0:
                ret += " !! Found duplicate labels ({}). When accessing custom fields the first record found will" \
                       "be returned.\n".format(",".join(problems))

        if len(record_dict["files"]) > 0:
            ret += "\n"
            table = Table(use_color=use_color)
            table.add_column("File Name", allow_wrap=True, data_color=Fore.GREEN)
            table.add_column("Type")
            table.add_column("Size", align=ColumnAlign.RIGHT)
            for file in record_dict["files"]:
                row = [file["title"], file["type"], "{:n}".format(int(file["size"]))]
                table.add_row(row)
            ret += table.get_string() + "\n"

        ret += "\n"

        return ret

    @staticmethod
    def _adjust_records(records, force_array):
        if type(records) is not list:
            records = [records]
        if force_array is False and len(records) == 1:
            records = records[0]
        return records

    def output_results(self, records, output_format, force_array, use_color=True):
        if output_format == 'text':
            for record_dict in records:
                self.cli.output(self._format_record(record_dict, use_color=use_color))
        elif output_format == 'json':
            self.cli.output(json.dumps(Secret._adjust_records(records, force_array), indent=4))
        else:
            return records

    @staticmethod
    def _get_jsonpath_results(data, expression, force_array=False):

        jsonpath_expression = parse(expression)
        results = [match.value for match in jsonpath_expression.find(data)]
        if force_array is False:
            if len(results) == 1:
                results = results[0]
        else:
            if type(results) is not list:
                results = [results]

        return results

    def _query_field(self, field_key, records):

        if len(records) == 0:
            raise Exception("No records found. Cannot find field {}.".format(field_key))

        # Can only perform field search on one record. The CLI part prevents this. Just grab the first record.
        record = records[0]
        field = None

        # First check the fields. Label first and then type.
        if record.get("fields") is not None:
            for key in ["label", "type"]:
                try:
                    field = next((item for item in record["fields"] if item.get(key) == field_key), None)
                except ValueError as _:
                    pass
                if field is not None:
                    break

        # If we don't have a value, check the custom_fields. Label first and then type.
        if field is None and record.get("custom_fields") is not None:
            for key in ["label", "type"]:
                if field is None or len(field) == 0:
                    try:
                        field = next((item for item in record["custom_fields"] if item.get(key) == field_key), None)
                    except ValueError as _:
                        pass
                if field is not None:
                    break

        if field is None:
            raise KsmCliException("Cannot find the field {} in record {}".format(field_key, record["title"]))

        value = field.get("value", [])
        if len(value) > 0:
            value = value[0]
        if type(value) is not str:
            value = json.dumps(value)

        print("", file=sys.stderr)
        self.cli.output(value)
        print("", file=sys.stderr)

    def _query_jsonpath(self, jsonpath_query, records, force_array):
        # Adjust records here so the JQ query works with the displayed JSON.
        record_list = Secret._adjust_records(records, force_array)

        try:
            results = self._get_jsonpath_results(record_list, jsonpath_query)
            self.cli.output(json.dumps(results, indent=4))
        except Exception as err:
            raise KsmCliException("JSONPath failed: {}".format(err))

    def query(self, uids=None, titles=None, field=None, output_format='json', jsonpath_query=None,
              force_array=False, load_references=False, unmask=False, use_color=None, inflate=True):

        if use_color is None:
            use_color = self.cli.use_color

        if uids is None:
            uids = []
        if titles is None:
            titles = []

        # If the output is JSON, automatically unmask password-like values.
        if output_format == 'json':
            unmask = True

        # If we want a specific field, then unmask the value
        if field is not None:
            unmask = True

        records = []
        fetch_uids = None

        # If we are not searching by title, then set the fetch uid to the uids passed in.
        if len(titles) == 0:
            fetch_uids = uids

        for record in self.cli.client.get_secrets(uids=fetch_uids):
            add_record = False

            # If we are searching by title, the fetch_uids was None, we have all the records. We need to filter
            # them by the title or uids.
            if len(titles) > 0:
                if record.title in titles or record.uid in uids:
                    add_record = True
            else:
                add_record = True

            if add_record is True:
                records.append(self._record_to_dict(record,
                                                    load_references=load_references,
                                                    unmask=unmask,
                                                    inflate=inflate))

        # The user wants a specific field value.
        if field is not None:
            self._query_field(
                field_key=field,
                records=records
            )
        # The user wants to use JSONPath to get the field(s) values.
        elif jsonpath_query is not None:
            self._query_jsonpath(
                jsonpath_query=jsonpath_query,
                records=records,
                force_array=force_array,
            )
        else:
            return self.output_results(records=records, output_format=output_format, force_array=force_array,
                                       use_color=use_color)

    @staticmethod
    def _format_list(record_dict, use_color=True):
        table = Table(use_color=use_color)
        table.add_column("UID", data_color=Fore.GREEN)
        table.add_column("Record Type")
        table.add_column("Title", data_color=Fore.YELLOW)
        for record in record_dict:
            table.add_row([record["uid"], record["type"], record["title"]])
        return "\n" + table.get_string() + "\n"

    def secret_list(self, uids=None, output_format='json', use_color=None):

        if use_color is None:
            use_color = self.cli.user_color

        record_dict = self.query(uids=uids, output_format='dict', unmask=True, use_color=use_color)
        if output_format == 'text':
            self.cli.output(self._format_list(record_dict, use_color=use_color))
        elif output_format == 'json':
            records = [{"uid": x.get("uid"), "title": x.get("title"), "record_type": x.get("type")}
                       for x in record_dict]
            self.cli.output(json.dumps(records, indent=4))

    def download(self, uid, name, file_output, create_folders=False):

        record = self.cli.client.get_secrets(uids=[uid])
        if len(record) == 0:
            raise KsmCliException("Cannot find a record for UID {}. Cannot download {}".format(uid, name))

        file = record[0].find_file_by_title(name)
        if file is None:
            raise KsmCliException("Cannot find a file named {} for UID {}. Cannot download file".format(name, uid))

        if file_output == 'stdout':
            sys.stderr.buffer.write(file.get_file_data())
        elif file_output == 'stderr':
            sys.stderr.buffer.write(file.get_file_data())
        elif type(file_output) is str:
            file.save_file(file_output, create_folders)
        else:
            raise KsmCliException("The file output {} is not supported. Cannot download and save the file.".format(
                file_output))

    def get_totp_code(self, uid):
        record = self.cli.client.get_secrets(uids=[uid])
        if len(record) == 0:
            raise KsmCliException("Cannot find a record for UID {}.".format(uid))

        totp_uri = None
        try:
            totp_uri = record[0].get_standard_field_value("oneTimeCode", True)
        except (Exception,):
            pass
        if not totp_uri:
            try:
                totp_uri = record[0].get_custom_field_value("oneTimeCode", True)
            except (Exception,):
                pass

        if not totp_uri:
            raise KsmCliException("Cannot find TOTP field for UID {}.".format(uid))

        try:
            totp = get_totp_code(totp_uri)
        except Exception as err:
            # The UI doesn't appear to valid the secret key, so the user might enter a bad secret key.
            if str(err) == 'Incorrect padding':
                raise KsmCliException("The secret key of the two factor code field appears to be invalid."
                                      " Please make sure the record is correct.")
            raise err

        self.cli.output(totp.code)

    def get_via_notation(self, notation):
        try:
            value = self.cli.client.get_notation(notation)
            if type(value) is dict or type(value) is list:
                value = json.dumps(value)
        except Exception as err:
            raise KsmCliException(str(err))

        return self.cli.output(value)

    @staticmethod
    def _split_kv(text, is_json=False, labels=None):

        """Split key/value.
        """

        # We need to know the label/types in the record. If we don't we can find the value.
        if labels is None:
            raise KsmCliException("Could not find any fields or custom_fields in the record.")

        #  Unwrap kv is quote wrapped. Only use ' and "
        # "label=value" or 'label=value'
        for quote in ["\'", "\""]:
            if text.startswith(quote) is True and text.endswith(quote) is True:
                text = text[1:-1]
                break

        # Our final values. Init to None
        key = None
        value = None

        for label in labels:
            if text.startswith("{}=".format(label)) is True:
                value = text.replace("{}=".format(label), "")
                key = label

        if key is None:
            raise KsmCliException("Cannot find the field/custom_field label or type for {}.".format(text))

        if is_json is True:
            try:
                value = json.loads(value)
                if type(value) is not list:
                    value = [value]
            except json.JSONDecodeError:
                raise KsmCliException("The value is not valid JSON for {}".format(text))

        return key, value

    def update(self, uid, fields=None, custom_fields=None, fields_json=None, custom_fields_json=None):

        record = self.cli.client.get_secrets(uids=[uid])
        if len(record) == 0:
            raise KsmCliException("Cannot find a record for UID {}.".format(uid))

        # Get a list of all labels/type allowed.
        labels = {
            "field": [x.get("label", x.get("type")) for x in record[0].dict.get("fields", [])],
            "custom_field": [x.get("label", x.get("type")) for x in record[0].dict.get("custom", [])]
        }

        data = [
            {"type": "field", "is_json": False, "values": fields},
            {"type": "custom_field", "is_json": False, "values": custom_fields},
            {"type": "field", "is_json": True, "values": fields_json},
            {"type": "custom_field", "is_json": True, "values": custom_fields_json},
        ]

        try:
            for item in data:
                if item["values"] is not None:
                    for kv in list(item["values"]):
                        key, value = self._split_kv(
                            kv,
                            is_json=item["is_json"],
                            labels=labels[item["type"]]
                        )
                        getattr(record[0], item["type"])(key, value)

        except Exception as err:
            raise KsmCliException("Could not update record: {}".format(err))

        try:
            self.cli.client.save(record[0])
        except Exception as err:
            raise KsmCliException("Could not save record: {}".format(err))

    def _check_if_can_add_records(self):
        # Check to see if appOwnerPublicKey is in the keeper.ini. It's a newly added key and if the
        # profile is too old we can't add a record.
        profile_config = self.cli.profile.get_profile_config(self.cli.profile.get_active_profile_name())
        if profile_config.get("appOwnerPublicKey") is None:
            raise KsmCliException("Your profile is out of date. It is missing the application order key. "
                                  "To create a record you will need to init a profile with a new token.")

    def add_record_interactive(self, version, folder_uid, record_type, output_format,
                               password_generate_flag, title=None, notes=None, editor=None):
        self._check_if_can_add_records()

        # If the editor was passed in, assume it doesn't need blocking.
        editor_use_blocking = False
        editor_process_name = None

        # If the editor was not passed in, use the editor set in the config. If not set, the code will
        # attempt to find and editor later.
        if editor is None:
            editor = self.cli.editor
            editor_use_blocking = self.cli.editor_use_blocking
            editor_process_name = self.cli.editor_process_name

        # Build a templated record with placeholders <#ADD>
        template = Record(version).get_template(
            record_type=record_type,
            output_format=output_format,
            title=title,
            notes=notes
        )

        temp_filename = None
        try:
            # Write the template file and close it. Windows doesn't like to share open files. The finally will handle
            # deleting  the file, so set delete=False so the tempfile doesn't delete it when closed.
            tf = tempfile.NamedTemporaryFile("w+", suffix=f".{output_format}", delete=False)
            temp_filename = tf.name
            tf.write(template)
            tf.close()

            launch_the_editor = True

            while True:

                if launch_the_editor is True:

                    # Launch the editor
                    launch_editor(
                        file=temp_filename,
                        editor=editor,
                        use_blocking=editor_use_blocking,
                        process_name=editor_process_name
                    )

                with open(temp_filename, 'r') as fh:
                    record_data = fh.read()
                    fh.close()
                    if re.search(r'<#ADD', record_data, re.MULTILINE) is not None:
                        print(Fore.RED + "Found template markers (#ADD) still in the record data. Either " +
                              "add a value or remove the line completely. Enter 'r' to recheck " +
                              "the file if the file was processed before you finished editing. " + Style.RESET_ALL)
                        ynq = input("Do you wish to edit? Y/n/r/q: ")
                        if ynq == "" or ynq[0].lower() == "y":
                            launch_the_editor = True
                            continue
                        if ynq[0].lower() == "r":
                            # If rechecking, don't launch the editor
                            launch_the_editor = False
                            continue
                        if ynq[0].lower() == "q":
                            print("Not adding record.")
                            return

                try:
                    # When saved, import the file
                    self.add_record_from_file(
                        folder_uid=folder_uid,
                        file=temp_filename,
                        password_generate_flag=password_generate_flag
                    )
                    # All is good break out of the loop
                    break
                except FileSyntaxException as err:
                    ynq = input(Fore.RED + str(err) + Style.RESET_ALL +
                                "Do you wish to edit and try again? Y/n/q: ")
                except Exception as err:
                    ynq = input(Fore.RED + f"Could not create the record: {err}. " + Style.RESET_ALL +
                                "Do you wish to edit and try again? Y/n/q: ")

                if ynq == "" or ynq[0].lower() == "y":
                    launch_the_editor = True
                    continue
                if ynq[0].lower() == "q":
                    print("Not adding record.")
                    return

        except Exception as err:
            raise KsmCliException(f"Could not edit the record template file: {err}")
        finally:
            if temp_filename is not None:
                os.unlink(temp_filename)

    def add_record_from_file(self, folder_uid, file, password_generate_flag):

        self._check_if_can_add_records()

        try:
            records = Record.create_from_file(file, password_generate=password_generate_flag)
            record_uids = []
            for record in records:
                record_create_obj = record.get_record_create_obj()
                record_uid = self.cli.client.create_secret(folder_uid, record_create_obj)
                record_uids.append(record_uid)
        except FileSyntaxException as err:
            raise KsmCliException(str(err))
        except Exception as err:
            raise KsmCliException(f"Could not load records from file {file}: {err}")

        print("The following is the new record UIDs in JSON ...", file=sys.stderr)
        return self.cli.output(json.dumps(record_uids))

    def add_record_from_field_args(self, version, folder_uid, password_generate_flag, record_type,
                                   title, notes, field_args):

        self._check_if_can_add_records()

        try:
            records = Record(version).create_from_field_args(
                record_type=record_type,
                title=title,
                notes=notes,
                field_args=field_args,
                password_generate=password_generate_flag
            )
            record = records[0]
            record_create_obj = record.get_record_create_obj()
            record_uid = self.cli.client.create_secret(folder_uid, record_create_obj)
        except Exception as err:
            raise KsmCliException(f"{err}")

        print("The following is the new record UID ...", file=sys.stderr)
        return self.cli.output(record_uid)

    def generate_password(self, length, lowercase, uppercase, digits, special_characters):

        new_password = sdk_generate_password(
            length=length,
            lowercase=lowercase,
            uppercase=uppercase,
            digits=digits,
            special_characters=special_characters
        )

        return self.cli.output(new_password)

    def get_record_type_template(self, record_type, output_format, version, file):

        if file is not None:
            self.cli.output_name = file
        return self.cli.output(Record(version).get_template(
            record_type=record_type,
            output_format=output_format
        ))

    def get_record_type_list(self, version):

        record_type_list = Record(version).get_template_list()

        table = Table(use_color=self.cli.use_color)
        table.add_column("Record Type", allow_wrap=True, data_color=Fore.GREEN)

        for record_type in record_type_list:
            table.add_row([record_type])

        return self.cli.output(table.get_string())

    def get_field_type_list(self, version):
        field_type_list = FieldType.get_field_type_list(version)

        table = Table(use_color=self.cli.use_color)
        table.add_column("Field Type", allow_wrap=True, data_color=Fore.GREEN)

        for field_type in field_type_list:
            table.add_row([field_type])

        return self.cli.output(table.get_string())

    def get_field_type_schema(self, field_type, output_format, version):
        schema = FieldType.get_field_type_schema(field_type, version)

        if output_format == "json":
            return self.cli.output(json.dumps(schema, indent=4))

        return self.cli.output(yaml.dump(schema))
