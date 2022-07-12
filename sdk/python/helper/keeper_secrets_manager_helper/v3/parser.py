# -*- coding: utf-8 -*-

from keeper_secrets_manager_helper.v3.field_type import FieldType, get_field_type_map
from keeper_secrets_manager_helper.field import Field, FieldSectionEnum
import re


class Parser:

    def __init__(self):
        # Find all the field type classes and create a map from the the camelcase name to the FieldType class
        self.field_map = get_field_type_map()

    def parse_field(self, field_args):

        field_objs = []

        # Might look like a list, but it could be a set, convert it
        if isinstance(field_args, set) is True:
            field_args = list(field_args)

        if isinstance(field_args, list) is False:
            field_args = [field_args]

        for arg in field_args:

            # First check if the field section is defined in the arg. The default is the standard fields, or 'f'
            field_section = FieldSectionEnum.STANDARD
            field_section_match = re.match(r'^(?P<field_section>.)\.', arg)
            if field_section_match is not None:
                field_section_value = field_section_match.group('field_section')
                if field_section_value == "f":
                    field_section = FieldSectionEnum.STANDARD
                elif field_section_value == "c":
                    field_section = FieldSectionEnum.CUSTOM
                else:
                    raise ValueError(f"Field section can only be 'f' or 'c'. The value '{field_section_value}' is not"
                                     "not valid.")
                # Remove the f. or c. from the arg
                arg = arg[2:]

            # At this point a camelcase field type name should be at the front of the arg, followed by a "[" or "="
            field_type_match = re.match(r'^(?P<field_type>\w+)[.\[=]', arg)
            if field_type_match is None:
                raise ValueError("Cannot find the field type name.")
            field_type = field_type_match.group("field_type")
            if field_type not in self.field_map:
                raise ValueError("Field type '{}' does not exists.".format(field_type))

            # This key designating what would make a complete field record unique. It used in grouping data into
            # a field record. It's like a primary key. See the Phones/Phone field type.
            group_key = self.field_map[field_type].group_key
            allow_multiple = self.field_map[field_type].allow_multiple

            # Remove the field type from the arg
            arg = arg[len(field_type):]

            field_label = None
            value_key = None

            while True:
                next_char = arg[0]
                arg = arg[1:]

                # Is the next thing a label for the field.
                if next_char == "[":

                    # Labels are weird. We need to character nibble this because the label contains a ]
                    # ie f.phone[\[BRACKETS\]]=... label = [BRACKETS]
                    # So we need to handle [, ], \ with special care.
                    index = 0
                    found_end = False
                    escape_mode = False
                    buffer = ""
                    while index < len(arg):
                        c = arg[index]
                        index += 1
                        # If we get the end ] and we are not in escape mode, we are done
                        if c == "]" and escape_mode is False:
                            found_end = True
                            break
                        # If we get a \ and we are not in escape mode, then turn on escape mode and disregard this char.
                        # This basically prevent use completing if we get a ]
                        elif c == "\\" and escape_mode is False:
                            escape_mode = True
                        else:
                            buffer += c
                            # Turn off escape mode since we got a character.
                            if escape_mode is True:
                                escape_mode = False

                    if found_end is False:
                        raise ValueError("Could not find the end of the label.")

                    if buffer != "":
                        field_label = buffer

                    # The + 1 is the end ]
                    arg = arg[index:]

                # If the next thing is a sub value of the value (ie street1 of Address)
                elif next_char == ".":

                    # If we have already gotten the sub value, then there is an error in the argument being parsed.
                    if value_key is not None:
                        raise ValueError(f"The value key '{value_key}' has already been found.")

                    # Get the text left of the =. Including the [ too.
                    sub_value_match = re.match(r'^(?P<sub_value_key>[\w_]+)[\[=.]', arg)
                    if sub_value_match is not None:
                        value_key = sub_value_match.group("sub_value_key")
                        schema = self.field_map[field_type].schema
                        value_type = schema.get("value_type")

                        # The value type might be another FieldType, get that FieldType's schema and value type
                        if issubclass(value_type, FieldType):
                            schema = value_type.schema
                            value_type = schema.get("value_type")

                        # If the value type is not a dictionary then we couldn't be using a value key. Throw
                        # an exception.
                        if value_type is not dict:
                            raise ValueError("The field type '{}' does not have value keys. "
                                             "Cannot set the value key {}.".format(field_type, value_key))

                        # If the value key is not in the dictionary, throw an exception.
                        schema = schema.get("schema")
                        if value_key not in schema:
                            raise ValueError("The field type '{}' does not have the value key '{}'. ".format(
                                field_type, value_key))

                        # The value key was found, use it.
                        arg = arg[len(value_key):]

                # Else we have the value
                else:
                    value = arg
                    break

            field_objs.append(
                Field(
                    field_section=field_section,
                    type=field_type,
                    label=field_label,
                    value_key=value_key,
                    group_key=group_key,
                    value=value,
                    allow_multiple=allow_multiple
                )
            )

        return field_objs
