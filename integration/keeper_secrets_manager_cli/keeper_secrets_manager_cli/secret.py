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
from keeper_secrets_manager_core.exceptions import KeeperError, KeeperAccessDenied
from .table import Table, ColumnAlign
import uuid


class Secret:

    # Type in custom_fields to type in fields dictionary
    support_ref_types = {
        "addressRef": "address"
    }
    redact_str = "****"
    redact_placeholder = "___" + str(uuid.uuid4()) + "___"
    redact_type_list = ['password', 'secret', 'pinCode', 'securityQuestion', 'oneTimeCode']

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

    def _record_to_dict(self, record, load_references=False, unmask=False, use_color=True):
        custom_fields = []
        raw_custom_fields = record.dict.get('custom', [])

        # If we have custom fields check in any have references that can replace with actual values
        if len(raw_custom_fields) > 0 and load_references is True:

            # Find all the custom fields that have a reference type and remember their index into the array. We
            # will use the index into the array to add the real values.
            index = 0
            replacement_data = {}
            for custom_field in raw_custom_fields:

                # If this is a maskable field and we are not going to unmask there is no need to load in the
                # reference value.
                if unmask is False and Secret._should_mask(custom_field):
                    continue

                field_type = custom_field.get("type")
                value = custom_field.get("value")

                # If the type of the custom field is a supported reference type then add their value to list
                # if uid to query. We are doing this in one shot so we don't get throttled.
                if field_type in Secret.support_ref_types:
                    for uid in value:
                        replacement_data[uid] = {"index": index, "type": field_type}
                    # Make a placeholder for the real values
                    custom_field["value"] = []
                index += 1

            # If we have replacement values, then get them and add their values with the real values
            if len(replacement_data) > 0:
                real_records = self.cli.client.get_secrets([uid for uid in replacement_data])
                for real_record in real_records:
                    if real_record.uid in replacement_data:
                        replacement_index = replacement_data[real_record.uid]["index"]
                        replacement_type = replacement_data[real_record.uid]["type"]
                        replacement_key = Secret.support_ref_types[replacement_type]
                        real_values = real_record.field(replacement_key)
                        for value in real_values:
                            raw_custom_fields[replacement_index]["value"].append(value)

            for custom_field in raw_custom_fields:
                field_type = custom_field.get("type")
                value = custom_field.get("value")

                # Should we mask the values?
                if unmask is False and Secret._should_mask(custom_field):
                    value = Secret._redact_value(value, use_color)

                custom_fields.append({
                    "label": custom_field.get("label", field_type),
                    "type": field_type,
                    "value": value
                })

        ret = {
            "uid": record.uid,
            "title": record.title,
            "type": record.type,
            "fields": [
                {
                    "type": x["type"],
                    "value": Secret._redact_value(x["value"], use_color) if unmask is False and Secret._should_mask(x)
                    else x["value"]
                } for x in record.dict.get('fields', [])
            ],
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
            table.add_row([field["type"], value])
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

    def query(self, uids=None, output_format='json', jsonpath_query=None, raw=False, force_array=False,
              text_join_char='\n', load_references=False,  unmask=False, use_color=True):

        # If the output is JSON, automatically unmask password-like values.
        if output_format == 'json':
            unmask = True

        records = []
        try:
            for record in self.cli.client.get_secrets(uids=uids):
                records.append(self._record_to_dict(record, load_references=load_references, unmask=unmask))
        except KeeperError as err:
            sys.exit("Could not query the records: {}".format(err.message))
        except KeeperAccessDenied as err:
            sys.exit("Could not query the records: {}".format(err.message))
        except Exception as err:
            sys.exit("Could not query the records: {}".format(err))

        if jsonpath_query is not None:

            # Adjust records here so the JQ query works with the displayed JSON.
            record_list = Secret._adjust_records(records, force_array)

            try:
                results = self._get_jsonpath_results(record_list, jsonpath_query)

                if output_format == 'text':
                    allow_raw_convert = True
                    if type(results) is dict:
                        results = json.dumps(results)
                        allow_raw_convert = False
                    elif type(results) is list:
                        results = text_join_char.join(results)
                        allow_raw_convert = False

                    # Only remove quotes if the value was non-dict, non-list
                    if allow_raw_convert is True and raw is True:
                        if results.startswith('"') is True:
                            results = results[1:]
                        if results.endswith('"') is True:
                            results = results[:-1]
                    self.cli.output(results)
                elif output_format == 'json':
                    self.cli.output(json.dumps(results, indent=4))
                else:
                    return results
            except Exception as err:
                sys.exit("JSONPath failed: {}".format(err))
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
            sys.exit("Cannot find a record for UID {}. Cannot download {}".format(uid, name))

        file = record[0].find_file_by_title(name)
        if file is None:
            sys.exit("Cannot find a file named {} for UID {}. Cannot download file".format(name, uid))

        if file_output == 'stdout':
            sys.stderr.buffer.write(file.get_file_data())
        elif file_output == 'stderr':
            sys.stderr.buffer.write(file.get_file_data())
        elif type(file_output) is str:
            file.save_file(file_output, create_folders)
        else:
            sys.exit("The file output {} is not supported. Cannot download and save the file.".format(file_output))

    def get_via_notation(self, notation):
        try:
            value = self.cli.client.get_notation(notation)
            if type(value) is dict or type(value) is list:
                value = json.dumps(value)
        except Exception as err:
            sys.exit(err)

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
            raise ValueError("The key/value format is invalid for '{}'.".format(text))

        return key, value

    def update(self, uid, fields=None, custom_fields=None):

        record = self.cli.client.get_secrets(uids=[uid])
        if len(record) == 0:
            sys.exit("Cannot find a record for UID {}.".format(uid))

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
            sys.exit("Could not update record: {}".format(err))

        try:
            self.cli.client.save(record[0])
        except Exception as err:
            sys.exit("Could not save record: {}".format(err))
