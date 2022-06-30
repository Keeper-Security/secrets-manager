# -*- coding: utf-8 -*-

from keeper_secrets_manager_helper.field import Field, FieldSectionEnum
from keeper_secrets_manager_helper.common import load_file
from keeper_secrets_manager_helper.v3.record_type import get_class_by_type as get_record_type_class
from keeper_secrets_manager_helper.v3.field_type import get_class_by_type as get_field_type_class
from importlib import import_module


class Record:

    @staticmethod
    def create_from_file(file, password_generate=False):
        record_data = load_file(file)
        return Record.create_from_data(record_data, password_generate=password_generate)

    @staticmethod
    def create_from_data(record_data, password_generate=False):

        records = []

        if record_data.get("version") != "v3":
            raise ValueError(".version is not 'v3'")
        if record_data.get("kind") != "KeeperRecord":
            raise ValueError(".kind is not 'KeeperRecord'")
        data = record_data.get("data")
        if data is None:
            raise ValueError(".data[] is missing")
        if isinstance(data, list) is False:
            raise ValueError(".data[] is not an array")

        record_count = 0
        for record_item in data:
            record_type = record_item.get("recordType", record_item.get("record_type"))
            if record_type is None or record_type == "":
                raise ValueError(f".data[{record_count}].recordType is missing or blank")
            title = record_item.get("title")
            if title is None or title == "":
                raise ValueError(f".data[{record_count}].title is missing or blank")

            record = Record(
                record_type=record_type,
                title=title,
                notes=record_item.get("notes"),
                password_generate=password_generate
            )

            all_fields = []

            fields = record_item.get("fields")
            if fields is None:
                raise ValueError(f".data[{record_count}].fields[] is missing")
            if isinstance(fields, list) is False:
                raise ValueError(f".data[{record_count}].fields[] is not an array")

            for field_item in fields:
                field = Field(
                    type=field_item.get("type"),
                    field_section=FieldSectionEnum.STANDARD,
                    label=field_item.get("label"),
                    value=field_item.get("value"),
                )
                all_fields.append(field)

            custom_fields = record_item.get("customFields", record_item.get("custom_fields"))
            if custom_fields is not None:
                if isinstance(custom_fields, list) is False:
                    raise ValueError(f".data[{record_count}].fields[] is not an array")

                for field_item in custom_fields:
                    field = Field(
                        type=field_item.get("type"),
                        field_section=FieldSectionEnum.CUSTOM,
                        label=field_item.get("label"),
                        value=field_item.get("value"),
                    )
                    all_fields.append(field)

            record.add_fields(all_fields)
            record.build_record()
            records.append(record)

        return records

    def __init__(self, *args, **kwargs):

        # If there is an arg, then assume it's a dictionary with record data.
        if len(args) > 0:
            pass

        self.record_type = kwargs.get("record_type")
        self.title = kwargs.get("title")
        self.notes = kwargs.get("notes")
        self.fields = []
        self.custom_fields = []

        if self.record_type is None or self.record_type == "":
            raise ValueError("record_type is missing or blank.")

        try:
            record_type = get_record_type_class(self.record_type)()

            # Make a quick lookup for the standard fields.
            self._valid_fields = [{"type": x.get("type"), "label": x.get("label"), "has_value": False}
                                  for x in record_type.get_standard_fields()]
        except ImportError as err:
            raise ValueError(err)

        if self.title is None or self.title == "":
            raise ValueError("title is missing or blank.")

        # The fields are mapped here in an attempt to make unique fields.
        self._fields = {
            FieldSectionEnum.STANDARD: {},
            FieldSectionEnum.CUSTOM: {}
        }

        self.password_generate = kwargs.get("password_generate", False)
        self.password_complexity = kwargs.get("password_complexity", None)

        self.valid_fields = []

        # All the fields (standard/custom) to be passed in with the constructor.
        fields = kwargs.get("fields")
        if fields is not None:
            self.add_fields(fields)
            self.build_record()

    def _add_new_field(self, field, field_key, group_key):
        # Count the number of keys in the dictionary and use that for an index. That will be used determine
        # the order.
        field.index = len(self._fields[field.field_section])

        # If the group key is not None, then convert the value to an array.
        if group_key is not None and isinstance(field.value, list) is False:
            field.value = [field.value]

        self._fields[field.field_section][field_key] = field

    def _is_valid_standard_field(self, field_type):
        for item in self._valid_fields:
            if item.get("type") == field_type and item.get("has_value") is False:
                return True
        return False

    def _flag_standard_field_used(self, field_type):
        for item in self._valid_fields:
            if item.get("type") == field_type and item.get("has_value") is False:
                item["has_value"] = True
                break

    def _get_label_for_standard_field(self, field_type):
        for item in self._valid_fields:
            if item.get("type") == field_type and item.get("has_value") is False:
                return item.get("label")
        return None

    def add_fields(self, fields):
        if isinstance(fields, list) is False:
            fields = [fields]

        for field in fields:

            if isinstance(field, Field) is False:
                raise ValueError("The method add_field requires instance(s) of Field")

            #
            label = None
            if field.field_section == FieldSectionEnum.STANDARD:
                label = self._get_label_for_standard_field(field.type)

            field_key = field.instance_field_key(label=label)
            group_key = field.group_key

            # Does this key already exists? And can we add values to the dictionary value?
            if field_key in self._fields[field.field_section] and field.can_add_key_value():

                # If out value is a string we should not be in here.
                if isinstance(field.value, str) is True:
                    raise ValueError(f"The {field.type} is a string. If JSON check to see if JSON is valid.")

                # Get the existing field and copy any values in it's dictionary into the existing.
                existing_field = self._fields[field.field_section][field_key]

                # If the field is completely set
                if existing_field.is_complete is True and existing_field.field_section == FieldSectionEnum.STANDARD:
                    raise ValueError("Attempting to set a standard field that has already been set.")

                # The existing field is complete and a custom field, so add
                if existing_field.is_complete is True:
                    raise ValueError("Cannot add this field due to it not being unique. To make unique add a label to "
                                     "the field or make sure the label is not being duplicated.")

                # If the existing_field is JSON and the current field is JSON, then add to existing. This allows
                # the value to be set with multiple objects.
                if existing_field.initial_value_was_json and field.initial_value_was_json:
                    if isinstance(existing_field.value, dict) is True:
                        existing_field.value = [existing_field.value]
                    if isinstance(field.value, list) is True:
                        for item in field.value:
                            existing_field.value.append(item)
                    else:
                        existing_field.value.append(field.value)
                    continue

                for k, v in field.value.items():

                    # If tke group key is set. The value can be multiple dictionaries that have a specific key
                    # which indicates its uniqueness. If that key does not exist, values can be inserted into the
                    # last dictionary in the list. If does exists, then a new dictionary is created.
                    if group_key is not None:
                        found_a_place = False
                        for item in existing_field.value:
                            if group_key not in item and item.get(Field.complete_key) is not True:
                                item[k] = v
                                found_a_place = True
                            else:
                                item[Field.complete_key] = True
                        if found_a_place is False and isinstance(existing_field.value, list) is True:
                            new_object = {k: v}
                            existing_field.value.append(new_object)
                    elif isinstance(existing_field.value, dict) is True:
                        existing_field.value[k] = v

            # Else we are creating a new entry.
            else:
                # Standard fields are defined. Don't insert a field that doesn't belong.
                if field.field_section == FieldSectionEnum.STANDARD:
                    if self._is_valid_standard_field(field.type):
                        self._flag_standard_field_used(field.type)
                    else:
                        raise ValueError(f"The standard fields do not have a '{field.type}' "
                                         "field type or they all have values.")

                self._add_new_field(field, field_key, group_key)

    @staticmethod
    def _copy_record_type_settings(field_obj, standard_field):
        # Copy extra values from the record type schema to the field. These are unique field type params like
        # required, enforce_generation and complexity.
        for key, value in standard_field.items():
            field_obj.add_extra(key, value)

    def _get_standard_fields(self, record_type):

        # Add the standard fields in the order defined by record type schema.

        fields_list = []
        # Get a list of standard fields in the Record Type.
        for standard_field in record_type.get_standard_fields():
            # First check if we have a key with a label, if it exists, and then use that.
            field_key = Field.field_key(standard_field.get("type"), standard_field.get("label"))
            if field_key in self._fields[FieldSectionEnum.STANDARD]:
                field_obj = self._fields[FieldSectionEnum.STANDARD][field_key]
                self._copy_record_type_settings(field_obj, standard_field)
                fields_list.append(field_obj)
            else:
                # Find the field by it's field type.
                field_key = Field.field_key(standard_field.get("type"), None)
                if field_key in self._fields[FieldSectionEnum.STANDARD]:
                    field_obj = self._fields[FieldSectionEnum.STANDARD][field_key]
                    self._copy_record_type_settings(field_obj, standard_field)
                    fields_list.append(field_obj)
                else:
                    # If nothing exists, make an empty field for the field type
                    field_obj = Field(
                        type=standard_field.get("type"),
                        field_section=FieldSectionEnum.STANDARD,
                        value=None
                    )
                    self._copy_record_type_settings(field_obj, standard_field)
                    fields_list.append(field_obj)

        return fields_list

    def _get_custom_fields(self):

        def get_index_key(obj):
            return obj.index

        # Add the custom fields in the order they were added.
        fields_list = [self._fields[FieldSectionEnum.CUSTOM][x] for x in self._fields[FieldSectionEnum.CUSTOM]]
        fields_list.sort(key=get_index_key)
        return fields_list

    @staticmethod
    def _remove_private_keys(obj):
        """
        The value might contain dictionaries what contain private key. This will remove any that exists. Right
        now it's just one.
        """
        if isinstance(obj, list):
            for item in obj:
                Record._remove_private_keys(item)
        elif isinstance(obj, dict):
            obj.pop(Field.complete_key, None)

    def build_record(self):

        record_type = get_record_type_class(self.record_type)()

        # Take all the standard fields from the user's input and populate the field type to validate it. Then
        # the dictionary used in the V3 records for a field to the list.
        self.fields = []
        for field in self._get_standard_fields(record_type):
            field_type_kwargs = field.to_dict()
            self._remove_private_keys(field_type_kwargs.get("value"))
            field_type_kwargs["password_generate"] = self.password_generate
            if self.password_complexity is not None:
                field_type_kwargs["complexity"] = self.password_complexity
            field_type_obj = get_field_type_class(field.type)(**field_type_kwargs)
            self.fields.append(field_type_obj.to_dict())

        # Do the same with the custom fields.
        self.custom_fields = []
        for field in self._get_custom_fields():
            field_type_kwargs = field.to_dict()
            self._remove_private_keys(field_type_kwargs.get("value"))
            field_type_kwargs["password_generate"] = self.password_generate
            if self.password_complexity is not None:
                field_type_kwargs["complexity"] = self.password_complexity
            field_type_obj = get_field_type_class(field.type)(**field_type_kwargs)
            self.custom_fields.append(field_type_obj.to_dict())

    def get_record_create_obj(self):
        try:
            # Make sure the classes we need are in the KSM Python SDK.
            mod = import_module("keeper_secrets_manager_core.dto.dtos")
            if hasattr(mod, "RecordCreate") is False:
                raise ImportError("Cannot find the RecordCreate in the KSM Python SDK. Please update the SDK.")
            record_field_class = getattr(mod, "RecordField")
            if record_field_class is None:
                raise ImportError("Cannot find the RecordField in the KSM Python SDK. Please update the SDK.")

            # Make an instance of the SDK's RecordCreate
            new_record = getattr(mod, "RecordCreate")(
                record_type=self.record_type,
                title=self.title
            )

            # Add the standard fields thru RecordField constructor
            record_field = []
            for field in self.fields:

                # Translate dictionary to RecordField
                field["field_type"] = field.pop("type")

                # V3 does take complexity or enforceGeneration
                field.pop("complexity", None)
                field.pop("enforceGeneration", None)

                record_field.append(record_field_class(**field))
            new_record.fields = record_field

            # Add the custom fields thru RecordField constructor
            record_field = []
            for field in self.custom_fields:
                # Translate dictionary to RecordField
                field["field_type"] = field.pop("type")

                # V3 does take complexity or enforceGeneration
                field.pop("complexity", None)
                field.pop("enforceGeneration", None)

                record_field.append(record_field_class(**field))
            new_record.custom = record_field

            # Add the notes
            new_record.notes = self.notes

        except ImportError as _:
            raise Exception("Cannot build a CreateRecord instance. Cannot find the KSM Python SDK.")

        return new_record
