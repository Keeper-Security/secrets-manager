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
from jsonpath_rw_ext import parse
import sys
from collections import deque
from colorama import Fore, Style
from keeper_secrets_manager_cli.exception import KsmCliException
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.utils import get_totp_code
from .table import Table, ColumnAlign
import uuid


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
                ret += " !! Found duplicate labels ({}). When accessing custom fields the first record found will be "\
                       "returned.\n".format(",".join(problems))

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
        try:
            field = next((item for item in record["fields"] if item["type"] == field_key), None)
        except ValueError as _:
            pass
        if field is None or len(field) == 0:
            try:
                field = next((item for item in record["custom_fields"] if item["label"] == field_key), None)
            except ValueError as _:
                pass
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
              force_array=False, load_references=False,  unmask=False, use_color=True, inflate=True):

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
        if len(titles) == 0:
            fetch_uids = uids

        for record in self.cli.client.get_secrets(uids=fetch_uids):
            add_record = False
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

        if field is not None:
            self._query_field(
                field_key=field,
                records=records
            )
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

    def secret_list(self, uids=None, output_format='json', use_color=True):

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
        except Exception:
            pass
        if not totp_uri:
            try:
                totp_uri = record[0].get_custom_field_value("oneTimeCode", True)
            except Exception:
                pass

        if not totp_uri:
            raise KsmCliException("Cannot find TOTP field for UID {}.".format(uid))

        try:
            totp, ttl, period = get_totp_code(totp_uri)
        except Exception as err:
            # The UI doesn't appear to valid the secret key, so the user might enter a bad secret key.
            if str(err) == 'Incorrect padding':
                raise KsmCliException("The secret key of the two factor code field appears to be invalid."
                                      " Please make sure the record is correct.")
            raise err

        self.cli.output(totp)

    def get_via_notation(self, notation):
        try:
            value = self.cli.client.get_notation(notation)
            if type(value) is dict or type(value) is list:
                value = json.dumps(value)
        except Exception as err:
            raise KsmCliException(err)

        return self.cli.output(value)

    @staticmethod
    def _split_kv(text):

        """Split key/value.

        Since we allow custom labels, the labels could include a '=' character so we can't just
        split a string on a '=' and call it a day.

        If a custom label has a '=' the user needs to escape it with a '\' character.

        For example, if we had a label like "==TOTAL==", the user would have to escape the '=' like
        this "\=\=TOTAL\=\='"so not to interfere the key/value separator. The final text would look like

        =\=TOTAL\=\==VALUE

        And the custom label has a "\" that now needs to be escaped "\\"

        """

        # Split the text by a =. Then build a key
        text_parts = deque(text.split("="))

        def _build_string(parts):
            string = parts.popleft()

            # While the key ends with a '\' and it's not a '\\', append the next value array
            while string.endswith("\\") is True:

                # Don't add a = is the escape character is escaped :/
                if string.endswith("\\\\") is False:
                    # Remove the escape character and replace it a '='
                    string = string[:-1]
                    string += "="
                    string += parts.popleft()
                # The string must have had a foo\\=. The = isn't escape, but the escape character escaped. Just
                # break. This is a an edge case.
                else:
                    break

            return string

        try:
            key = _build_string(text_parts)
            value = _build_string(text_parts)

            # The key/value might have been surrounded with quotes. Remove them
            if key.startswith('"') is True:
                key = key[1:]
                if value.endswith('"') is True:
                    value = value[:-1]
        except Exception:
            raise KsmCliException("The key/value format is invalid for '{}'.".format(text))

        return key, value

    def update(self, uid, fields=None, custom_fields=None):

        record = self.cli.client.get_secrets(uids=[uid])
        if len(record) == 0:
            raise KsmCliException("Cannot find a record for UID {}.".format(uid))

        try:
            if fields is not None:
                for kv in list(fields):
                    key, value = self._split_kv(kv)
                    record[0].field(key, value)
            if custom_fields is not None:
                for kv in list(custom_fields):
                    key, value = self._split_kv(kv)
                    record[0].custom_field(key, value)
        except Exception as err:
            raise KsmCliException("Could not update record: {}".format(err))

        try:
            self.cli.client.save(record[0])
        except Exception as err:
            raise KsmCliException("Could not save record: {}".format(err))
