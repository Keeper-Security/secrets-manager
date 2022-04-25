from ansible.plugins.callback.default import CallbackModule as DefaultCallbackBase
from ansible.plugins.callback import strip_internal_keys, module_response_deepcopy
import json
import re

DOCUMENTATION = '''
    name: keeper_redact
    type: stdout
    short_description: Redact Keeper secrets from task results
    version_added: historical
    description:
        - This output callback will hide secret values from the output of a task.
        - This output callback will not hide secret values from a lookup. Use no_log: True to hide the output.
    extends_documentation_fragment:
      - default_callback
    requirements:
      - set as stdout in configuration
'''


class CallbackModule(DefaultCallbackBase):

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'keeper_redact'

    KEEPER_KEYS = [
        "keeper_config",
        "keeper_config_file",
        "keeper_client_id",
        "keeper_private_key",
        "keeper_app_key"
    ]

    def __init__(self):
        super(CallbackModule, self).__init__()

    @staticmethod
    def _remove_special_keeper_values(obj):
        if type(obj) is list:
            for item in obj:
                CallbackModule._remove_special_keeper_values(item)
        elif type(obj) is dict:
            for k, v in obj.items():
                if type(v) is dict or type(v) is list:
                    CallbackModule._remove_special_keeper_values(v)
                else:
                    if k in CallbackModule.KEEPER_KEYS:
                        obj[k] = "****"

    def _dump_results(self, result, indent=None, sort_keys=True, keep_invocation=False, serialize=True):

        if result.get('_ansible_no_log', False) is True:
            # Shamefully taken from the yaml callback. Keep same error message since people might be used
            # to it.
            return json.dumps(dict(
                censored="The output has been hidden due "
                         "to the fact that 'no_log: true' was specified for this result"))

        clean_result = strip_internal_keys(module_response_deepcopy(result))

        # Remove keeper config vars that are secret.
        self._remove_special_keeper_values(clean_result)

        json_result = json.dumps(clean_result, indent=4)

        # If we have secrets, then remove them from results, sort them in descending lengths, and make a
        # regular expression to replace them with ****
        secrets = result.pop("_secrets", None)
        if secrets is not None and len(secrets) > 0:
            # Sort secret from longest to shortest
            sorted_secrets = sorted(secrets, key=len, reverse=True)
            for item in sorted_secrets:
                json_result = json_result.replace(str(item), "****")

        return json_result
