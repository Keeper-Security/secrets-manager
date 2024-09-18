# -*- coding: utf-8 -*-

import re
import json
import inspect
import sys
import random
from importlib import import_module
import keeper_secrets_manager_helper.format
from keeper_secrets_manager_helper.v3.enum import BaseEnum, PhoneTypeEnum, CountryEnum, AccountTypeEnum


UID_REGEX = r'^[a-zA-Z0-9\-_]{22}$'

field_map = {}


# Find all the field type classes and create a map from the the camelcase name to the FieldType class
def get_field_type_map():
    global field_map
    if len(field_map) == 0:
        for item in inspect.getmembers(sys.modules[__name__], inspect.isclass):
            mod_class = getattr(sys.modules[__name__], item[0])
            if mod_class is not None:
                field_type_class = getattr(sys.modules[__name__], "FieldType")
                if issubclass(mod_class, field_type_class) is True:
                    class_name = getattr(mod_class, "name")
                    if class_name is None:
                        continue
                    field_map[class_name] = mod_class
        field_map = field_map

    return field_map


def get_class_by_type(class_name):
    get_field_type_map()
    if class_name in field_map:
        return field_map[class_name]
    raise ImportError("Field type class {} does not exists.".format(class_name))


def get_field_type_list():
    return list(get_field_type_map().keys())


def get_field_type_schema(field_type):
    get_field_type_map()

    def _expand_value_type(schema):

        allow_multiple = schema.get("allow_multiple", False)
        value_type = schema.get("value_type")
        # If the record doesn't set allow_multiple to True/False, allow the field to set the value.
        if issubclass(value_type, FieldType) is True:
            new_schema = value_type.schema
            return _expand_value_type(new_schema)
        elif issubclass(value_type, BaseEnum) is True:
            value = "<#ADD: " + value_type.build_example() + ">"
            return value
        elif issubclass(value_type, dict):
            value_block = {}
            for key, info in schema.get("schema").items():
                value_block[key] = _expand_value_type(info)
            return value_block
        else:
            value = "<#ADD: " + schema.get("desc", "Insert a {}".format(value_type.__name__)) + ">"
            if allow_multiple is True:
                value = [value]
            return value

    data = {
        "type": field_type
    }

    if field_type not in field_map:
        raise ValueError("Field type '{}' does not exists.".format(field_type))
    field_type_obj = field_map[field_type]
    field_schema = field_type_obj.schema
    data["value"] = _expand_value_type(field_schema)
    data["privacyScreen"] = field_schema.get("privacy_screen", False)
    field_type_obj.add_template_specifics(data)

    return data


class PasswordComplexity:

    def __init__(self, value=None, length=64, caps=0, lowercase=0, digits=0, special=0, filter_characters=None):

        # If a dictionary is passed in, use that get the attributes.
        if value is not None and type(value) is dict:
            length = value.get("length", length)
            caps = value.get("caps", caps)
            lowercase = value.get("lowercase", lowercase)
            digits = value.get("digits", digits)
            special = value.get("special", special)
            filter_characters = value.get("filter_characters", filter_characters)

        self.length = length
        self.caps = caps
        self.lowercase = lowercase
        self.digits = digits
        self.special = special

        self.filter_characters = filter_characters
        if isinstance(self.filter_characters, str):
            self.filter_characters = []
            self.filter_characters.extend(filter_characters)

    def to_dict(self):

        return {
            "length": self.length,
            "caps": self.caps,
            "lowercase": self.lowercase,
            "digits": self.digits,
            "special": self.special,
            "filter_characters": self.filter_characters
        }

    def replacement_char(self):

        """
        Get a replacement character that doesn't match the bad character.
        """

        new_char = None
        all_true = (self.lowercase + self.caps + self.digits + self.special) == 0

        attempt = 0
        while True:
            # If allow everything, then just get a lowercase letter
            if all_true is True:
                new_char = "abcdefghijklmnopqrstuvwxyz"[random.randint(0, 25)]

            # Else we need to find the first allowed character set.
            else:
                pick_one = random.randint(0, 3)
                if pick_one == 0 and self.lowercase > 0:
                    new_char = "abcdefghijklmnopqrstuvwxyz"[random.randint(0, 25)]
                if pick_one == 1 and self.caps > 0:
                    new_char = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random.randint(0, 25)]
                if pick_one == 2 and self.digits > 0:
                    new_char = "0123456789"[random.randint(0, 9)]
                if pick_one == 3 and self.special > 0:
                    new_char = "!@#$%^&*()"[random.randint(0, 9)]

                if new_char is None:
                    continue

            # If our new character is not in the list of bad characters, break out of the while
            if new_char not in self.filter_characters:
                break

            # Ok, some user might go crazy and filter out every letter, digit, and symbol and cause an invite loop.
            # If we can't find a good character after 25 attempts, error out.
            attempt += 1
            if attempt > 25:
                raise ValueError("Cannot filter character from password. The password complexity is too complex.")

        return new_char

    def filter_password(self, password):

        for bad_char in self.filter_characters:
            while bad_char in password:
                password = password.replace(bad_char, self.replacement_char(), 1)
        return password

    def generate_password(self):
        try:
            mod = import_module("keeper_secrets_manager_core.utils")
            password = getattr(mod, "generate_password")(
                length=self.length,
                lowercase=self.lowercase,
                uppercase=self.caps,
                digits=self.digits,
                special_characters=self.special
            )

            # If we have a character filter, remove bad characters
            if self.filter_characters is not None:
                password = self.filter_password(password)

        except ImportError as _:
            raise Exception("Cannot generate a random password. Requires keeper-secrets-manager-core module.")

        return password


class FieldType:
    schema = {"value_type": str}
    name = None

    # In a field that allows multiple FieldType, is there a "primary key" that makes a dictionary entry unique.
    # This use for Phones, which can many Phone entries, and if we need to figure out what is unique.
    group_key = None

    # Are multiple values allowed
    allow_multiple = False

    def __init__(self, *args, **kwargs):
        self._value = None

        # If the value is passed in, set it/overwrite the value in kwargs.
        if len(args) > 0:
            kwargs["value"] = args[0]

        # Get and remove the common keys
        value = kwargs.pop("value", None)
        label = kwargs.pop("label", None)
        required = kwargs.pop("required", None)
        privacy_screen = kwargs.pop("privacy_screen", None)

        # This will validate and set the value. If the value passed in is invalid, a ValueError exception is thrown.
        if value is not None:
            self.value = value

        self.label = label
        self.required = required
        self.privacy_screen = privacy_screen

        schema = self.get_schema()
        if schema.get("value_type") is dict:

            # Default to the passed in args for attribute variables. However if the value args exists, then use that
            # to get the attribute values.
            attr_dict = kwargs
            if self.value is not None:
                attr_dict = self.value[0]

            # This will create and set the attribute variables.
            for key in schema.get("schema", {}):
                setattr(self, key, attr_dict.get(key, None))

    def __str__(self):
        return f'{self.__class__.__name__}(label={self.label}, value={self.value}, required={self.required}, '\
               f'privacy_screen={self.privacy_screen})'

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, val):
        schema = self.get_schema()
        value_type = schema.get("value_type")

        if isinstance(val, list) is False:
            val = [val]

        # If the value of the field is another FieldType, convert raw value into an instance of that FieldType.
        if issubclass(value_type, FieldType) is True:
            for index in range(len(val)):
                if isinstance(val[index], value_type) is False:
                    # Create an instance, pass in value as the value and let the FieldType
                    val[index] = value_type(val[index])

        if self._is_valid(val) is True:
            self._value = val

    def add_value(self, new_value):
        val = self.value
        if val is None:
            val = []
        val.append(new_value)
        self.value = val

    def get_schema(self):
        schema = FieldType.schema
        if hasattr(self.__class__, "schema") is True:
            schema = self.__class__.schema

        return schema

    def get_type(self):
        return self.__class__.name

    @staticmethod
    def is_value_valid(value, schema, field_class):
        validator = schema.get("validate")
        value_type = schema.get("value_type")

        # The field value contains a dictionary of values.
        if value_type is dict:
            if type(value) is not dict:
                raise ValueError("The value is not a dictionary.")
            dict_schema = schema.get("schema")
            for key, info in dict_schema.items():
                # If the value is required, then make sure it exists and is not blank.
                if info.get("required", False) is True and (value.get(key) is None or value.get(key) == ""):
                    raise ValueError(f"The value key '{key}' is missing and it is required.")

                FieldType.is_value_valid(value.get(key), dict_schema.get(key), field_class)

        # The field value has an enumeration. Make sure the value is a valid value of the enumeration.
        elif value is not None and issubclass(value_type, BaseEnum):

            if value_type.enum_exists(value) is False:
                raise ValueError(f"The value of '{value}' for '{field_class}' is not valid.")

        # If the field value is a string, then it doesn't matter if an int, float, etc is passed in. However
        # we can do some validation on the value, so treat as string.
        elif value_type is str:
            if value is not None and validator is not None:
                value = str(value)
                validator_params = schema.get("validate_params", re.IGNORECASE)
                if re.match(str(validator), value, validator_params) is None:
                    raise ValueError(f"The value for' {field_class}' is not valid.")

        # Check if the value type is another FieldType, check the field type
        elif value is not None and isinstance(value_type, FieldType) is True:
            value_type.is_value_valid(value, schema, field_class)

    def _is_valid(self, value):
        schema = self.get_schema()
        for item in value:
            self.is_value_valid(item, schema, self.__class__.__name__)
        return True

    def build_value(self, schema, value=None, is_child:bool=False):

        value_type = schema.get("value_type")

        # If the value is an instance of FieldType
        if issubclass(value_type, FieldType) is True:
            return value.build_value(value_type.schema, None)

        # If the value type is an enumeration, get the value of the enumeration. The actual value may be
        # the enum or possible value. Find the right enum and get that enums value.
        elif issubclass(value_type, BaseEnum) is True:
            if value is None:
                return None
            return value_type.get_value(value)

        # If the value is a dictionary, then we are getting the values from the instance's attributes.
        elif value_type is dict:

            new_schema = schema.get("schema")
            value_dict = {}
            # Get the key and its schema.
            for key, info in new_schema.items():
                dict_value = None
                if not is_child:
                    # Get the value from the instance's attribute.
                    dict_value = self.build_value(info, getattr(self, key), is_child=True)
                else:
                    # Get value from dict /current value/
                    if value and key in value:
                        dict_value = self.build_value(info, value.get(key), is_child=True)

                if dict_value is not None:
                    value_dict[key] = dict_value

            return value_dict

        # At this point, we are a simple data type (99.999% we are str).
        else:
            if value is not None:
                if schema.get("format") is not None:
                    # This will take the value from the attribute and format, and validate it, into the desired
                    # format
                    value = self.format_value(
                        format_type=schema.get("format"),
                        value=value
                    )
            return value

    def to_dict(self):
        schema = self.get_schema()

        # Add the field camel case name of the class.
        field_dict = {
            "type": self.get_type()
        }
        # Add additional properties only if they are not blank. This is based on Vault UI behavior.
        if self.label is not None and self.label != "":
            field_dict["label"] = self.label
        if self.required is not None:
            field_dict["required"] = self.required
        if self.privacy_screen is not None:
            field_dict["privacyScreen"] = self.privacy_screen

        new_values = []

        # self.value is a list of values. We need to check them all.
        values = self.value
        if values is None:
            values = []

        # If the value is a dictionary, there is no value in self.value
        # since the value comes from the attributes. We need to fake values,
        # so set it one item of None. It won't be used, but a for loop will need it.
        if schema.get("value_type") is dict:
            values = [None]

        # Build add the values.
        for item in values:
            new_value = self.build_value(schema, item)
            self.is_value_valid(new_value, schema, self.__class__.__name__)
            new_values.append(new_value)

        field_dict["value"] = new_values

        return field_dict

    def to_json(self):
        return json.dumps(self.to_dict())

    @staticmethod
    def format_value(format_type, value):
        if hasattr(keeper_secrets_manager_helper.format, format_type) is True:
            return getattr(keeper_secrets_manager_helper.format, format_type)(value)
        raise ValueError("Could not find formatter {}".format(format_type))

    @staticmethod
    def add_template_specifics(data):
        pass

# -------------------------------------------------------------------------------------------------------------------


class Text(FieldType):
    name = "text"


class Url(FieldType):
    name = "url"


class PinCode(FieldType):
    name = "pinCode"


class Multiline(FieldType):
    name = "multiline"


# "file" - obsolete and removed legacy field - "fldt_file": { key: 'file_or_photo', default: "File or Photo" },
class FileRef(FieldType):
    name = "fileRef"
    # The validation checks to see if value is a Record UID.
    schema = {"value_type": str, "validate": UID_REGEX, "desc": "Record UID of File record."}


class Email(FieldType):
    name = "email"


class Phone(FieldType):
    name = "phoneItem"
    schema = {
        "value_type": dict,
        "schema": {
            "region": {"value_type": str, "desc": "Region"},
            "number": {"value_type": str, "desc": "Number"},
            "ext": {"value_type": str, "desc": "Extension"},
            "type": {"value_type": PhoneTypeEnum}
        }
    }


class Phones(FieldType):
    name = "phone"
    group_key = "type"
    allow_multiple = True
    schema = {"value_type": Phone}


class Name(FieldType):
    name = "name"
    schema = {
        "value_type": dict,
        "schema": {
            "first": {"value_type": str, "desc": "First Name"},
            "middle": {"value_type": str, "desc": "Middle name"},
            "last": {"value_type": str, "desc": "Last Name"}
        }
    }


class Address(FieldType):
    name = "address"
    schema = {
        "value_type": dict,
        "schema": {
            "street1": {"value_type": str, "desc": "Street"},
            "street2": {"value_type": str, "desc": "Street 2"},
            "city": {"value_type": str, "desc": "City"},
            "state": {"value_type": str, "desc": "State"},
            "zip": {"value_type": str, "desc": "Zip/Postal Code"},
            "country": {"value_type": CountryEnum, "desc": "ISO3166 Alpha-2 Country Code"},
        }
    }


class AddressRef(FieldType):
    name = "addressRef"
    # The validation checks to see if value is a Record UID.
    schema = {"value_type": str, "validate": UID_REGEX, "desc": "Record UID for Address record."}


class AccountNumber(FieldType):
    name = "accountNumber"


class Login(FieldType):
    name = "login"


class HiddenField(FieldType):
    name = "secret"


class Password(FieldType):
    name = "password"
    schema = {"value_type": str, "desc": "Password or Remove If Generating"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._enforce_generation = None
        self._complexity = None

        self.enforce_generation = kwargs.pop("enforce_generation", None)
        self.complexity = kwargs.pop("complexity", None)
        self.password_generate = kwargs.pop("password_generate", None)

    def __str__(self):
        return f'{self.__class__.__name__}(label={self.label}, value={self.value}, required={self.required}, '\
               f'privacy_screen={self.privacy_screen}, enforce_generation={self.enforce_generation}'

    @property
    def enforce_generation(self):
        return self._enforce_generation

    @enforce_generation.setter
    def enforce_generation(self, value):
        if value is not None and type(value) is not bool:
            raise ValueError("enforce_generation needs to be a boolean value.")
        self._enforce_generation = value

    @property
    def complexity(self):
        return self._complexity

    @complexity.setter
    def complexity(self, value):
        if value is not None:
            if type(value) is dict:
                value = PasswordComplexity(value)
            if isinstance(value, PasswordComplexity) is not True:
                raise ValueError("complexity needs to be a PasswordComplexity instance.")
        self._complexity = value

    @staticmethod
    def add_template_specifics(data):
        data["enforceGeneration"] = False
        data["complexity"] = PasswordComplexity().to_dict()

    def to_dict(self):

        # If enforceGeneration is enabled in the record type or password_generate is True and the password has not
        # been set, then generate a password, ignore the value that is already there.
        if self.enforce_generation is True or (self.value is None and self.password_generate is True):
            self.generate_password()

        field_dict = super().to_dict()
        if self.enforce_generation is not None:
            field_dict["enforceGeneration"] = self.enforce_generation
        if self.complexity is not None:
            field_dict["complexity"] = self.complexity.to_dict()
        return field_dict

    def generate_password(self):
        if self.complexity is None:
            self.complexity = PasswordComplexity()
        self.value = [self.complexity.generate_password()]


class SecurityQuestions(FieldType):
    name = "securityQuestion"
    schema = {
        "value_type": dict,
        "schema": {
            "question": {"value_type": str, "desc": "Security Question"},
            "answer": {"value_type": str, "desc": "Answer To The Question"}
        }
    }


class OneTimePassword(FieldType):
    name = "otp"
    schema = {"value_type": str, "validate": r'^otpauth://', "desc": "URL starting with otpauth://"}


class OneTimeCode(FieldType):
    name = "oneTimeCode"
    schema = {"value_type": str, "validate": r'^otpauth://', "desc": "URL starting with otpauth://"}


class CardRef(FieldType):
    name = "cardRef"
    # The validation checks to see if value is a Record UID.
    schema = {"value_type": str, "validate": UID_REGEX, "desc": "Record UID of PaymentCard record."}


class PaymentCard(FieldType):
    name = "paymentCardItem"
    schema = {
        "value_type": dict,
        "schema": {
            "cardNumber": {"value_type": str, "desc": "Card Number"},
            "cardExpirationDate": {"value_type": str, "validate": r'^\d{2}\/\d{4}$',
                                   "desc": "Expiration Date as MM/YYYY"},
            "cardSecurityCode": {"value_type": str}
        }
    }


class PaymentCards(FieldType):
    name = "paymentCard"
    schema = {"value_type": PaymentCard}


class Date(FieldType):
    name = "date"
    schema = {"value_type": str, "format": "date_to_ms", "desc": "Date in ISO8601 Format or Epoch Milliseconds"}


class BirthDate(FieldType):
    name = "birthDate"
    schema = {"value_type": str, "format": "date_to_ms", "desc": "Birth Date in ISO8601 Format or Epoch Milliseconds"}


class ExpirationDate(FieldType):
    name = "expirationDate"
    schema = {"value_type": str, "format": "date_to_ms",
              "desc": "Expiration Date in ISO8601 Format or Epoch Milliseconds"}


class BankAccount(FieldType):
    name = "bankAccountItem"
    schema = {
        "value_type": dict,
        "schema": {
            "accountType": {"value_type": AccountTypeEnum},
            "otherType": {"value_type": str, "desc": "Other Type Description"},
            "routingNumber": {"value_type": str, "desc": "Routing Number"},
            "accountNumber": {"value_type": str, "desc": "Account Number"},
        }
    }


class BankAccounts(FieldType):
    name = "bankAccount"
    schema = {"value_type": BankAccount}


class KeyPair(FieldType):
    name = "keyPair"
    schema = {
        "value_type": dict,
        "schema": {
            "publicKey": {"value_type": str, "desc": "Public Key"},
            "privateKey": {"value_type": str, "desc": "Private Key. Normally a PEM file."},
        }
    }


class Host(FieldType):
    name = "host"
    schema = {
        "value_type": dict,
        "schema": {
            "hostName": {"value_type": str, "desc": "Hostname or IP"},
            "port": {"value_type": str, "desc": "Port"},
        }
    }


class LicenseNumber(FieldType):
    name = "licenseNumber"
    schema = {"value_type": str, "desc": "License Number"}


class SecureNote(FieldType):
    name = "note"
    schema = {"value_type": str, "desc": "Secret Note"}


class RecordRef(FieldType):
    name = "recordRef"
    # The validation checks to see if value is a Record UID.
    schema = {"value_type": str, "validate": UID_REGEX, "desc": "Record UID of the referenced record."}


class Schedule(FieldType):
    name = "schedule"
    schema = {
        "value_type": dict,
        "schema": {
            "type": {"value_type": str, "desc": "Type"},
            "cron": {"value_type": str, "desc": "Crontab format string"},
            # "utcTime" - replaced by time and tz
            "time": {"value_type": str, "desc": "Time"},
            "tz": {"value_type": str, "desc": "Time zone"},
            "weekday": {"value_type": str, "desc": "Day of the Week"},
            "intervalCount": {"value_type": int, "desc": "Interval Count"}
        }
    }


class DirectoryType(FieldType):
    name = "directoryType"
    schema = {"value_type": str, "desc": "Directory Type"}


class DatabaseType(FieldType):
    name = "databaseType"
    schema = {"value_type": str, "desc": "Database Type"}


class PamHostname(FieldType):
    name = "pamHostname"
    schema = {
        "value_type": dict,
        "schema": {
            "hostName": {"value_type": str, "desc": "Hostname or IP"},
            "port": {"value_type": str, "desc": "Port"},
        }
    }


class PamResources(FieldType):
    name = "pamResources"
    schema = {
        "value_type": dict,
        "schema": {
            "controllerUid": {"value_type": str, "desc": "Record UID of the Controller Record"},
            "folderUid": {"value_type": str, "desc": "Folder UID"},
            "resourceRef": {"value_type": list, "desc": "List with UIDs of resource records"},
            "allowedSettings": {
                "value_type": dict, "desc": "List with allowed settings flags",
                "schema": {
                    "connections": {"value_type": bool},
                    "portForwards": {"value_type": bool},
                    "rotation": {"value_type": bool},
                    "sessionRecording": {"value_type": bool},
                    "typescriptRecording": {"value_type": bool}
                }},
        }
    }


class Checkbox(FieldType):
    name = "checkbox"
    schema = {"value_type": bool, "desc": "Checkbox"}


class Passkey(FieldType):
    name = "passkey"
    schema = {
        "value_type": dict,
        "schema": {
            "privateKey": {"value_type": dict, "desc": "Private EC Key.",
            "schema": {
                "crv": {"value_type": str},
                "d": {"value_type": str},
                "ext": {"value_type": bool},
                "key_ops": {"value_type": list},
                "kty": {"value_type": str},
                "x": {"value_type": str},
                "y": {"value_type": str}
            }},
            "credentialId": {"value_type": str, "desc": "Credential Id"},
            "signCount": {"value_type": int, "desc": "Sign Count"},
            "userId": {"value_type": str, "desc": "User Id"},
            "relyingParty": {"value_type": str, "desc": "Relying Party"},
            "username": {"value_type": str, "desc": "User Name"},
            "createdDate": {"value_type": str, "format": "date_to_ms", "desc": "Creation Date in ISO8601 Format or Epoch Milliseconds"}
        }
    }


class Script(FieldType):
    name = "script"
    schema = {
        "value_type": dict,
        "schema": {
            "fileRef": {"value_type": str, "validate": UID_REGEX, "desc": "Record UID of File record."},
            "command": {"value_type": str, "desc": "Command"},
            "recordRef": {"value_type": str, "validate": UID_REGEX, "desc": "Record UID of the referenced record."}
        }
    }


class IsSSIDHidden(FieldType):
    name = "isSSIDHidden"
    schema = {"value_type": bool, "desc": "Is SSID Hidden"}


class WifiEncryption(FieldType):
    name = "wifiEncryption"


class Dropdown(FieldType):
    name = "dropdown"


class RbiUrl(FieldType):
    name = "rbiUrl"


class AppFiller(FieldType):
    name = "appFiller"
    schema = {
        "value_type": dict,
        "schema": {
            "applicationTitle": {"value_type": str, "desc": "Application Title"},
            "contentFilter": {"value_type": str, "desc": "Content Filter"},
            "macroSequence": {"value_type": str, "desc": "Macro Sequence"},
        }
    }


class PamRemoteBrowserSettings(FieldType):
    name = "pamRemoteBrowserSettings"
    schema = {
        "value_type": dict,
        "schema": {
            "connection": {
                "value_type": dict,
                "desc": "Connection details",
                "schema": {
                    "protocol": {"value_type": str},
                    "userRecords": {"value_type": list},
                    "allowUrlManipulation": {"value_type": bool},
                    "allowedUrlPatterns": {"value_type": str},
                    "allowedResourceUrlPatterns": {"value_type": str},
                    "httpCredentialsUid": {"value_type": str},
                    "autofillConfiguration": {"value_type": str}
                }
            },
        }
    }


class PamSettings(FieldType):
    name = "pamSettings"
    schema = {
        "value_type": dict,
        "schema": {
            "connection": {
                "value_type": dict,
                "desc": "PAM Settings",
                "schema": {
                    "portForward": {
                        "value_type": list,
                        "desc": "Port Settings",
                        "schema": {
                            "reusePort": {"value_type": bool},
                            "port": {"value_type": str},
                        }
                    },
                    "connection": {
                        "value_type": list,
                        "desc": "Connection Settings",
                        "schema": {
                            "protocol": {"value_type": str},
                            "userRecords": {"value_type": list},
                            "security": {"value_type": str},
                            "ignoreCert": {"value_type": bool},
                            "resizeMethod": {"value_type": str},
                            "colorScheme": {"value_type": str}
                        }
                    },
                }
            },
        }
    }


class TrafficEncryptionSeed(FieldType):
    name = "trafficEncryptionSeed"


# List of retired field types:
# trafficEncryptionKey - replaced by trafficEncryptionSeed
# pamProvider - deprecated for legacy/internal use only
# controller - deprecated for legacy/internal use only
