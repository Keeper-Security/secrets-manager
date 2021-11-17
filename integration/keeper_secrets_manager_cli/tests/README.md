Run test from the top level of the project. Tests are using the module name:

    integration.keeper_secrets_manager_cli.keeper_secrets_manager_cli.KeeperCli.get_client

for mocking. If run from the keeper_secrets_manager_cli directory, the mock patch needs to be changed to

    keeper_secrets_manager_cli.KeeperCli.get_client