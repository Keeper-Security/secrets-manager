from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage

if __name__ == '__main__':

    hostname = input("Enter KSM Server\nPress <Enter> to use keepersecurity.com server: ")
    if not hostname:
        hostname = "keepersecurity.com"

    token = input("Enter one time token: ")
    print("Hostname: [" + hostname + "]")
    print("Token: [" + token + "]")

    secrets_manager = SecretsManager(
## if your Keeper Account is in other region than US, update the hostname accordingly
        hostname=hostname,
        token=token,
        config=FileKeyValueStorage(),
    )

    all_records = secrets_manager.get_secrets()

    for r in all_records:

        # view record data details
        print("\tPassword: %s" % r.password)
        print("\tRecord details: %s" % r.dict)

        # view all files in record if present
        count = 0
        for f in r.files:
            count = count + 1
            print("\t\t%s file: %s" % (count, f))

            file_path = "/tmp/" + f.name

            f.save_file(file_path, create_folders=True)
