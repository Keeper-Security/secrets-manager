from enum import Enum
import json


class FieldSectionEnum(Enum):
    STANDARD = "f"
    CUSTOM = "c"


class Field:

    def __init__(self, **kwargs):

        self.type = kwargs.pop("type", None)
        self.field_section = kwargs.pop("field_section", None)
        self.label = kwargs.pop("label", None)
        self._value = None
        self.value = kwargs.pop("value", None)

        value_key = kwargs.pop("value_key", None)
        if value_key is not None and isinstance(self.value, dict) is False:
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
                except json.JSONDecodeError:
                    pass
            if val == "":
                val = None
        self._value = val

    def __str__(self):
        return f'Field(type={self.type}, field_section={self.field_section}, label={self.label}, '\
               f'value_key={self.value_key}, value={self.value}, index={self.index}, extra={self.extra}, '\
               f'group_key={self.group_key}'

    def add_extra(self, key, value):
        if hasattr(self, key) is False:
            self.extra[key] = value

    @staticmethod
    def field_key(field_type, label):
        return "{}/{}".format(field_type, label)

    def instance_field_key(self):
        return self.field_key(self.type, self.label)

    def can_add_key_value(self):
        return isinstance(self.value, dict) is True or self.group_key is not None

    def to_dict(self):
        data = {
            "type": self.type,
            "label": self.label,
            "value": self.value,
        }
        return {**data, **self.extra}
