function Register-KeeperVault
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [string] $OneTimeToken
    )
    
    $result = [SecretManagement.Keeper.Client]::SetVaultConfig($OneTimeToken, $Name).GetAwaiter().GetResult()
    if ($result.IsFailure) {
        Write-Error $result.ErrorMsg
        return
    }
    Microsoft.Powershell.SecretManagement\Register-SecretVault -Name $Name ./SecretManagement.Keeper.psd1
}