function Register-KeeperVault
{
    [CmdletBinding()]
    param (
#         [Parameter(Mandatory = $true)]
#         [string] $Name,
#         [Parameter(Mandatory = $true)]
        [string] $OneTimeToken,
        [string] $LocalVaultModule
    )

    Write-Host getting by lit 1    
    Get-Secret -Name aa -Vault SecretStore
    
#     $configSecretName = 'KeeperVault.' + $Name
#     Write-Host $configSecretName
    $LocalVaultModule = if ($PSBoundParameters.ContainsKey('LocalVaultModule')) { $LocalVaultModule } else { 'Microsoft.PowerShell.SecretStore' }
    $moduleInstance = Import-Module -Name $LocalVaultModule -PassThru -ErrorAction Stop
#     
    Write-Host getting by literal
    & $moduleInstance { Get-Secret aa }
    
    Write-Host getting by lit 2    
    Get-Secret -Name aa -Vault SecretStore
    
# 
#     Write-Host getting by name
#     & $moduleInstance { Get-Secret $Name }
    
#     & $moduleInstance { Set-Secret -Name $configSecretName -Secret 'abcd' }
#     & $moduleInstance { Set-Secret -Name KeeperVault.K2 -Secret 'abcd' }
#     $result = [SecretManagement.Keeper.Client]::GetVaultConfig($OneTimeToken).GetAwaiter().GetResult()
#     if ($result.IsFailure) {
#       Write-Error $result.ErrorMessage 
#       return
#     }
#     Write-Host $configSecretName
#     Write-Host $result.Data
#     & $moduleInstance { Set-Secret -Name $configSecretName -Secret $result.Data -VaultName SecretStore }
#     Microsoft.Powershell.SecretManagement\Register-SecretVault -Name $Name ./SecretManagement.Keeper.psd1
}