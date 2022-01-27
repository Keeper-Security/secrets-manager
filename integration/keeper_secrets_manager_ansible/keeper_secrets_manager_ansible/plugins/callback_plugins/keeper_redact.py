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

    def __init__(self):
        super(CallbackModule, self).__init__()

    def _dump_results(self, result, indent=None, sort_keys=True, keep_invocation=False, serialize=True):

        if result.get('_ansible_no_log', False) is True:
            # Shamefully taken from the yaml callback. Keep same error message since people might be used
            # to it.
            return json.dumps(dict(
                censored="The output has been hidden due "
                         "to the fact that 'no_log: true' was specified for this result"))

        # If we have secrets, then remove them from results, sort them in descending lengths, and make a
        # regular expression to replace them with ****
        secrets = result.pop("_secrets", None)
        redact_regexp = None
        if secrets is not None and len(secrets) > 0:
            reg_exp_items = []
            # Sort secret from longest to shortest
            sorted_secrets = sorted(secrets, key=len, reverse=True)
            for item in sorted_secrets:
                # Escape an regular expression characters. Item will be ansible.utils.unsafe_proxy.AnsibleUnsafeText,
                # which we will just convert to a str.
                reg_exp_items.append(re.escape(str(item)))
            redact_regexp = "|".join(reg_exp_items)

        clean_result = strip_internal_keys(module_response_deepcopy(result))

        json_result = json.dumps(clean_result, indent=4)
        if redact_regexp is not None:
            json_result = re.sub(redact_regexp, '****', json_result, re.MULTILINE)

        return json_result
