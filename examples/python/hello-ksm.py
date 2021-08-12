from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage

if __name__ == '__main__':

    secrets_manager = SecretsManager(
        hostname='keepersecurity.com',
        token='<ONE TIME TOKEN>',
        config=FileKeyValueStorage(),
    )

    all_records = secrets_manager.get_secrets()

    for r in all_records:

        print("\tPassword: %s" % r.password)

        print("\tRecord details:\n%s" % r.dict)

        count = 0
        for f in r.files:
            count = count + 1
            print("\t\t%s file: %s" % (count, f))

            file_path = "/tmp/" + f.name

            f.save_file(file_path, create_folders=True)
