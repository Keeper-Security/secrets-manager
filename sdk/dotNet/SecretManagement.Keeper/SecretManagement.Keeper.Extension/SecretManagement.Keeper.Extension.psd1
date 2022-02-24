@{
    ModuleVersion = '16.2.0'
    RootModule = 'SecretManagement.Keeper.Extension.psm1'
    RequiredAssemblies = '../SecretManagement.Keeper.dll'    
    CompatiblePSEditions = @('Core')
    GUID = '7ad471fa-c303-4e0f-8da7-4b4b6da380f9'
    Author = 'Sergey Aldoukhov'
    CompanyName = 'Keeper Security'
    Copyright = '(c) 2021 Keeper Security, Inc.'
    FunctionsToExport = 'Set-Secret', 'Get-Secret', 'Remove-Secret', 'Get-SecretInfo', 'Test-SecretVault', 'Set-KeeperVault'
    CmdletsToExport = @()    
    VariablesToExport = @()
    AliasesToExport = @()
}

