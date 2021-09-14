@{
    ModuleVersion = '1.0'
    RootModule = '.\SecretManager.Keeper.dll'
    NestedModules = @('.\SecretManager.Keeper.Extension')
#     CmdletsToExport = @('Set-TestStoreConfiguration','Get-TestStoreConfiguration')
    PrivateData = @{
        PSData = @{
            Tags = @('SecretManagement')
        }
    }
}