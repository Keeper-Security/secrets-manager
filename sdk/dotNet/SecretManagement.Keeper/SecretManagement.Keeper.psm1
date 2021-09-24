function Register-KeeperVault
{
    [CmdletBinding()]
    param (
#         [Parameter(Mandatory = $true)]
        [string] $Name,
#         [Parameter(Mandatory = $true)]
        [string] $OneTimeToken,
        [string] $LocalVaultModule
    )
    
    $LocalVaultModule = if ($PSBoundParameters.ContainsKey('LocalVaultModule')) { $LocalVaultModule } else { 'Microsoft.PowerShell.SecretStore' }
    $moduleInstance = Import-Module -Name $LocalVaultModule -PassThru -ErrorAction Stop
#         # Run SecretStore extension vault command using module scope
# #     & $moduleInstance { Set-Secret -Name bb "Hello again" }        
#     $secret = & $moduleInstance { Get-Secret -Name aa }
    Write-Host 'here'
    
    $config = [SecretManagement.Keeper.Client]::GetVaultConfig($OneTimeToken, $Name).GetAwaiter().GetResult()
#     if ($result.IsFailure) {
#         Write-Error $result.ErrorMsg
#         return
#     }
#     Microsoft.Powershell.SecretManagement\Register-SecretVault -Name $Name ./SecretManagement.Keeper.psd1
}