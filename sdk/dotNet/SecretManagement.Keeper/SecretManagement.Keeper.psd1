@{
    ModuleVersion = '0.1.0'
    CompatiblePSEditions = @('Core')
    GUID = '74bb5212-2a5d-451d-8f43-edf9bcd2efe8'
    Author = 'Sergey Aldoukhov'
    CompanyName = 'Keeper Security'
    Copyright = '(c) 2021 Keeper Security, Inc.'
    Description = 'SecretManagement extension vault for Keeper'
#     RootModule = './bin/Debug/netstandard2.0/SecretManagement.Keeper.dll'
    RootModule = './SecretManagement.Keeper.psm1'
    NestedModules = @('./SecretManagement.Keeper.Extension')
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Register-KeeperVault')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('SecretManagement')
            LicenseUri = 'bla'
            ProjectUri = 'bla'
            ReleaseNotes = 'Initial release'
        }
    }
}
