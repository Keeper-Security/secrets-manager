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

    Commander.server = 'https://dev.keepersecurity.com'
    Commander.config = FileKeyValueStorage("config-id1.json")
    Commander.verify_ssl_certs = False

    Commander.secret_key = 'eqHArsbplcKU-LX_ksOKIA5VTC-4Ak2O-Um22oyDHzs'

    all_records = Commander.all()





    for r in all_records:

        print(r)
        print("\tPassword: %s" % r.password)

        for f in r.files:
            print("\t\t-> %s" % f )

            f.save_file("/Users/mustinov/Downloads/_v2/___" + f.name, True)

    found_by_uid = Commander.get('id1-CORRECT REC FILE IN FOLDER 1')

    print(found_by_uid)

    rec_to_update = all_records[0]


    # raw_json = rec_to_update.raw_json
    # raw_dict = json_to_dict(raw_json)

    # fields = raw_dict['fields']


    # password_field = next((item for item in fields if item["type"] == "password"), None)
    #
    # password_field['value'] = ["New Password-" + str(datetime.now())]
    #
    # updated_raw_json = dict_to_json(raw_dict)
    #
    # rec_to_update.raw_json = updated_raw_json
    #
    # rec_to_update.uid = None
    #
    # Commander.save(rec_to_update)