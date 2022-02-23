import configparser
import tempfile
import base64
import json

from keeper_secrets_manager_core.utils import base64_to_bytes
from keeper_secrets_manager_core.keeper_globals import keeper_servers


class Export:

    def __init__(self, config, file_format=None, plain=False):
        self.config = config
        self.file_format = file_format
        self.plain = plain

    def run(self):

        config_str = None
        if self.file_format == "ini":
            config_str = self._format_ini()
        elif self.file_format == "json":
            config_str = self._format_json()

        if self.plain is False:
            if type(config_str) is str:
                config_str = config_str.encode()

            config_str = base64.urlsafe_b64encode(config_str)

        return config_str

    def _format_ini(self):

        from .profile import Profile

        export_config = configparser.ConfigParser()
        export_config[Profile.default_profile] = self.config
        export_config[Profile.config_profile] = {
            Profile.active_profile_key: Profile.default_profile
        }

        # Apparently the config parser doesn't like temp files. So create a
        # temp file, then open a file for writing and use that to write
        # the config. Then read the temp file to get our new config.
        with tempfile.NamedTemporaryFile() as tf:

            with open(tf.name, 'w') as configfile:
                export_config.write(configfile)

            tf.seek(0)
            config_str = tf.read()
            tf.close()

        return config_str

    def _format_json(self):

        mapping = {
            "clientId": {"key": "clientId", "isBase64": True},
            "privateKey": {"key": "privateKey", "isBase64": True},
            "appKey": {"key": "appKey", "isBase64": True},
            "hostname": {"key": "hostname", "isBase64": False, "transformMap": keeper_servers},
            "serverPublicKeyId": {"key": "serverPublicKeyId", "isBase64": False}
        }

        config_dict = {}

        for key, info in mapping.items():
            if key in self.config:
                if info["isBase64"] is True:
                    value_bytes = base64_to_bytes(self.config[key])
                    # Encode a non-url safe base64
                    config_dict[info["key"]] = base64.b64encode(value_bytes).decode()
                else:
                    if "transformMap" in info:
                        config_dict[info["key"]] = info["transformMap"].get(self.config[key], self.config[key])
                    else:
                        config_dict[info["key"]] = self.config[key]
        return json.dumps(config_dict, indent=4)
