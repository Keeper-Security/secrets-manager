@{
    ModuleVersion = '18.0.0'
    CompatiblePSEditions = @('Core')
    GUID = '20ab89cb-f0dd-4e8e-b276-f3a7708c1eb2'
    Author = 'Sergey Aldoukhov'
    CompanyName = 'Keeper Security'
    Copyright = '(c) 2024 Keeper Security, Inc.'
    Description = 'SecretManagement extension vault for Keeper'
    RootModule = './SecretManagement.Keeper.psm1'
    NestedModules = @('./SecretManagement.Keeper.Extension')
    PowerShellVersion = '7.6'
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
            ReleaseNotes = 'Requires PowerShell 7.6 or later. PowerShell 7.4 and 7.5 reached end of support on 2026-11-10. Users on PowerShell 7.5 can install version 17.1.2 with Install-Module -RequiredVersion 17.1.2. This release moves System.Text.Json to 10.0.15.'
        }
    }
}
