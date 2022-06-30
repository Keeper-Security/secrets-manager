# -*- coding: utf-8 -*-

from enum import Enum
import json


class FieldSectionEnum(Enum):
    STANDARD = "f"
    CUSTOM = "c"


class Field:

    complete_key = "_complete"

    def __init__(self, **kwargs):

        self.initial_value_was_json = None

        # If an array of values is passed in, then the field is complete.
        self.is_complete = False

        self.type = kwargs.pop("type", None)
        self.field_section = kwargs.pop("field_section", None)
        self.label = kwargs.pop("label", None)
        self.allow_multiple = kwargs.pop("allow_multiple", None)
        self._value = None
        self.value = kwargs.pop("value", None)

        value_key = kwargs.pop("value_key", None)
        if value_key is not None and isinstance(self.value, dict) is False:
            self.initial_value_was_json = False
            self.value = {
                value_key: self.value
            }
        self.value_key = value_key

        # Default at the way way way end.
        self.index = kwargs.pop("index", 1_000_000)

        self.group_key = kwargs.pop("group_key", None)

        self.extra = kwargs

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, val):
        if val is not None:
            # If the value JSON? Decode it if it is.
            if isinstance(val, str) is True:
                try:
                    val = json.loads(val)

                    # If the initial value was JSON, then flag it was and mark field as complete.
                    if self.initial_value_was_json is None:
                        if isinstance(val, list) is True:
                            self.is_complete = True
                            # Is complete, no need to flag any dictionary as comelete
                        elif isinstance(val, dict) is True:
                            val[Field.complete_key] = True
                        self.initial_value_was_json = True
                except json.JSONDecodeError:
                    self.initial_value_was_json = False
            if val == "":
                val = None
        self._value = val

    def __str__(self):
        return f'Field(type={self.type}, field_section={self.field_section}, label={self.label}, '\
               f'value_key={self.value_key}, value={self.value}, index={self.index}, extra={self.extra}, '\
               f'group_key={self.group_key}, initial_value_was_json={self.initial_value_was_json}'

    def add_extra(self, key, value):
        if hasattr(self, key) is False:
            self.extra[key] = value

    @staticmethod
    def field_key(field_type, label):
        return "{}/{}".format(field_type, label)

    def instance_field_key(self, label=None):
        return self.field_key(self.type, label if self.label is None else self.label)

    def can_add_key_value(self):
        return isinstance(self.value, dict) is True or self.group_key is not None

    def to_dict(self):
        data = {
            "type": self.type,
            "label": self.label,
            "value": self.value,
        }
        return {**data, **self.extra}
