@{
    ModuleVersion = '1.0'
    RootModule = '.\SecretManager.Keeper.psm1'
    RequiredAssemblies = '..\SecretManager.Keeper.dll'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault')
}