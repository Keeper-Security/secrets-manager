# -*- coding: utf-8 -*-

from .exception import FileSyntaxException
import yaml
import json
import re
import os


def load_file(file):
    is_json = re.search("json$", file, re.IGNORECASE) is not None
    if os.path.exists(file) is False:
        raise Exception(f"Cannot find the file {file}")
    with open(file, 'r') as fh:
        if is_json is True:
            try:
                record_data = json.loads(fh.read())
            except json.JSONDecodeError as err:
                raise FileSyntaxException(f"The JSON had problems: {err.msg} around row "
                                          f"{err.lineno}, column {err.colno}")
        else:
            try:
                record_data = yaml.load(fh.read(), Loader=yaml.BaseLoader)
            except yaml.YAMLError as err:
                if hasattr(err, 'problem_mark'):
                    mark = err.problem_mark
                    raise FileSyntaxException(f"The YAML has problems around row "
                                              f"{mark.line + 1}, column {mark.column + 1}.")
                raise FileSyntaxException("The YAML has problems.")
    return record_data


