#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
from datetime import datetime

from keepercommandersm import Commander
from keepercommandersm.storage import FileKeyValueStorage
from keepercommandersm.utils import json_to_dict, dict_to_json

if __name__ == '__main__':

    Commander.server = 'https://local.keepersecurity.com'
    Commander.config = FileKeyValueStorage("config-id2.json")
    Commander.verify_ssl_certs = False

    Commander.secret_key = 'KmsOqSq-aB0l7VraWHBHhMaZC2HYDDY5rJIgaP3qD7E'

    all_records = Commander.all()

    for r in all_records:

        print(r)
        print("\tPassword: %s" % r.password)

        count = 0
        for f in r.files:
            count = count + 1
            print("\t\tfile %s -> name: %s" % (count, f))

            f.save_file("/Users/mustinov/Downloads/_v2/___" + f.name, True)

    found_by_uid = Commander.get('id1-CORRECT REC FILE IN FOLDER 1')
    if found_by_uid:
        print(found_by_uid)

    rec_to_update = all_records[0]

    raw_json = rec_to_update.raw_json
    raw_dict = json_to_dict(raw_json)

    fields = raw_dict['fields']

    password_field = next((item for item in fields if item["type"] == "password"), None)

    password_field['value'] = ["New Password from SDK Test -" + str(datetime.now())]

    updated_raw_json = dict_to_json(raw_dict)

    rec_to_update.raw_json = updated_raw_json
    #
    # rec_to_update.uid = None

    Commander.save(rec_to_update)