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
import prettytable
from keeper_secrets_manager_core.exceptions import KeeperError, KeeperAccessDenied
from .common import table_setup


class Secret:

    # Type in custom_fields to type in fields dictionary
    support_ref_types = {
        "addressRef": "address"
    }

    def __init__(self, cli):
        self.cli = cli

    def _record_to_dict(self, record, load_references=False):
        custom_fields = []
        raw_custom_fields = record.dict.get('custom', [])

        # If we have custom fields check in any have references that can replace with actual values
        if len(raw_custom_fields) > 0 and load_references is True:

            # Find all the custom fields that have a reference type and remember their index into the array. We
            # will use the index into the array to add the real values.
            index = 0
            replacement_data = {}
            for custom_field in raw_custom_fields:
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
                    "value": x["value"]
                } for x in record.dict.get('fields')
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
    def _format_record(record_dict):
        ret = ""
        ret += " Record: {}\n".format(record_dict["uid"])
        ret += " Title: {}\n".format(record_dict["title"])
        ret += " Record Type: {}\n".format(record_dict["type"])
        ret += "\n"

        table = prettytable.PrettyTable()
        table.field_names = ["Field", "Value"]
        table_setup(table)
        for field in record_dict["fields"]:
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
            table.add_row([field["type"], value])
        ret += table.get_string() + "\n"

        if len(record_dict["custom_fields"]) > 0:
            ret += "\n"
            table = prettytable.PrettyTable()
            table.field_names = ["Custom Field", "Type", "Value"]
            table_setup(table)

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
            table = prettytable.PrettyTable(["File Name", "Type", "Size"])
            table_setup(table)
            table.align["Type"] = 'l'
            table.align["Size"] = 'r'
            for file in record_dict["files"]:
                row = [file["title"], file["type"], file["size"]]
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

    def output_results(self, records, output_format, force_array):
        if output_format == 'text':
            for record_dict in records:
                self.cli.output(self._format_record(record_dict))
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
              text_join_char='\n', load_references=False):

        records = []
        try:
            for record in self.cli.client.get_secrets(uids=uids):
                records.append(self._record_to_dict(record, load_references=load_references))
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
            return self.output_results(records=records, output_format=output_format, force_array=force_array)

    @staticmethod
    def _format_list(record_dict):
        table = prettytable.PrettyTable()
        table.field_names = ["UID", "Record Type", "Title"]
        table_setup(table)
        for record in record_dict:
            table.add_row([record["uid"], record["type"], record["title"]])
        return table.get_string() + "\n"

    def secret_list(self, uids=None, output_format='json'):

        record_dict = self.query(uids=uids, output_format='dict')
        if output_format == 'text':
            self.cli.output(self._format_list(record_dict))
        elif output_format == 'json':
            records = [{"uid": x["uid"], "title": x["title"], "record_type": x["type"]} for x in record_dict]
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
