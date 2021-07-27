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
from datetime import datetime

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage
from keeper_secrets_manager_core.utils import json_to_dict, dict_to_json

if __name__ == '__main__':

    secrets_manager = SecretsManager(
        hostname='https://dev.keepersecurity.com',
        token='hCDFN_tj9Enppq94PgyFqSeWeNvqAt_oDQ8YQnTMpL4',
        verify_ssl_certs=False,
        config=FileKeyValueStorage('config.json')
    )

    all_records = secrets_manager.get_secrets()

    for r in all_records:

        print(r)
        print("\tPassword: %s" % r.password)

        count = 0
        for f in r.files:
            count = count + 1
            print("\t\tfile %s -> name: %s" % (count, f))

            f.save_file("/tmp/" + f.name, True)

    rec_to_update = all_records[0]

    raw_json = rec_to_update.raw_json
    raw_dict = json_to_dict(raw_json)

    fields = raw_dict['fields']

    password_field = next((item for item in fields if item["type"] == "password"), None)

    if password_field:
        password_field['value'] = ["New Password from SDK Test -" + str(datetime.now())]

        updated_raw_json = dict_to_json(raw_dict)

        rec_to_update.raw_json = updated_raw_json
        #
        # rec_to_update.uid = None

        secrets_manager.save(rec_to_update)
    else:
        print("No records w/ password field was found")

    print("Get only one record")

    JW_F1_R1 = secrets_manager.get_secrets(['EG6KdJaaLG7esRZbMnfbFA'])

    print(JW_F1_R1)
