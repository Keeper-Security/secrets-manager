from . import KeeperAnsible, KeeperFieldType
import argparse


parser = argparse.ArgumentParser(description='Simple value retrieval')
parser.add_argument('--keeper_client_key', metavar='-c', type=str, required=False, help='client key')
parser.add_argument('--keeper_config_file', metavar='-cf', type=str, help='config file name', required=False)
parser.add_argument('--keeper_server', metavar='-s', type=str, help='config file name', required=False)
parser.add_argument('--uid', type=str, help='uid or title of record', required=False)
parser.add_argument('--field', metavar='-f', type=str, help='field name', default='password')
parser.add_argument('--field_type', metavar='-ft', type=str, help='field type', default='field')
args = parser.parse_args()

task_args = {
    "keeper_force_config_write": True
}
if args.keeper_client_key is not None:
    task_args["keeper_client_key"] = args.keeper_client_key
if args.keeper_config_file is not None:
    task_args["keeper_config_file"] = args.keeper_config_file
if args.keeper_server is not None:
    task_args["keeper_server"] = args.keeper_server

print("TASK ARGS", task_args)

keeper_ansible = KeeperAnsible(task_args)

if args.uid is not None:
    value = keeper_ansible.get_value(
        uid=args.uid,
        key=args.field,
        field_type=KeeperFieldType.get_enum(args.field_type)
    )
    print(value)
else:
    print("No uid/record title specified. If a JSON config didn't exist it has been created and can be used "
          "instead of specifying the client key.")
