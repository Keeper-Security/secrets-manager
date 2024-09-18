@{
    ModuleVersion = '16.6.7'
    CompatiblePSEditions = @('Core')
    GUID = '20ab89cb-f0dd-4e8e-b276-f3a7708c1eb2'
    Author = 'Sergey Aldoukhov'
    CompanyName = 'Keeper Security'
    Copyright = '(c) 2024 Keeper Security, Inc.'
    Description = 'SecretManagement extension vault for Keeper'
    RootModule = './SecretManagement.Keeper.psm1'
    NestedModules = @('./SecretManagement.Keeper.Extension')
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Register-KeeperVault')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('SecretManagement','Keeper','SecretVault','Vault','Secret','MacOS','Linux','Windows')
            LicenseUri = 'https://github.com/Keeper-Security/secrets-manager/blob/master/LICENSE'
            ProjectUri = 'https://github.com/Keeper-Security/secrets-manager'
            IconUri  = 'https://keeper-email-images.s3.amazonaws.com/common/powershell.png'
            ReleaseNotes = 'Bug fixes and improvements'
        }
    }
}
