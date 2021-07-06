Run test from the top level of the project. Tests are using the module name:

    integration.keeper_sm_cli.keeper_sm_cli.KeeperCli.get_client

for mocking. If run from the keeper_sm_cli directory, the mock patch needs to be changed to

    keeper_sm_cli.KeeperCli.get_client