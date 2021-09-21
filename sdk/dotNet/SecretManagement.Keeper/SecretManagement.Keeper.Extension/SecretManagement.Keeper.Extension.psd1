@{
    ModuleVersion = '0.1.0'
    RootModule = 'SecretManagement.Keeper.Extension.psm1'
    RequiredAssemblies = './bin/Debug/netstandard2.0/SecretManagement.Keeper.dll'    
    CompatiblePSEditions = @('Core')
    GUID = '6a4caa73-b31c-4df3-a751-9b96b1daf294'
    Author = 'Sergey Aldoukhov'
    CompanyName = 'Keeper Security'
    Copyright = '(c) 2021 Keeper Security, Inc.'
    FunctionsToExport = 'Set-Secret', 'Get-Secret', 'Remove-Secret', 'Get-SecretInfo', 'Test-SecretVault', 'Set-KeeperVault'
    VariablesToExport = @()
    AliasesToExport = @()
}

