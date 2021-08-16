from datetime import datetime

from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage, InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import json_to_dict, dict_to_json

if __name__ == '__main__':

    secrets_manager = SecretsManager(
## if your Keeper Account is in other region than US, update the hostname accordingly
        hostname='keepersecurity.com',
        token='<ONE TIME TOKEN>',
        config=FileKeyValueStorage('config2.json')
    )

    all_records = secrets_manager.get_secrets()

    # Get first record
    rec_to_update = all_records[0]

    raw_json = rec_to_update.raw_json
    raw_dict = json_to_dict(raw_json)

    fields = raw_dict['fields']

    # getting first field in a record of type password
    password_field = next((item for item in fields if item["type"] == "password"), None)

    if password_field:
        password_field['value'] = ["New Password from hello world -" + str(datetime.now())]

        updated_raw_json = dict_to_json(raw_dict)

        rec_to_update.raw_json = updated_raw_json

        # Perform save operation
        secrets_manager.save(rec_to_update)
    else:
        print("No records w/ password field was found")

    print("Get only one record by UID")

    found_record = secrets_manager.get_secrets(['<RECORD UID>'])

    print(found_record)
