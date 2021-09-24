function Get-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    return $null

#     return [SecretManagement.Keeper.Client]::GetSecret($Name, $VaultName).GetAwaiter().GetResult()
}

function Get-SecretInfo
{
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    return $null
    
#     $moduleName = 'Microsoft.PowerShell.SecretStore'
#     $moduleInstance = Import-Module -Name $moduleName -PassThru
#     $secret = & $moduleInstance { Get-Secret -Name aa }
#     Write-Host $secret
#     
#     $secrets = [SecretManagement.Keeper.Client]::GetSecretsInfo($Filter, $VaultName).GetAwaiter().GetResult()
#     
#     $secretsInfo = New-Object System.Collections.Generic.List[System.Object]
#     foreach ($secret in $secrets) {
#         $secretInfo = [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
#                           $secret,      # Name of secret
#                           "Hashtable",      # Secret data type [Microsoft.PowerShell.SecretManagement.SecretType]
#                           $VaultName,    # Name of vault
#                           $Metadata)
#         $secretsInfo.Add($secretInfo)                  
#     }
#     return $secretsInfo
}

function Set-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [object] $Secret,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    $result = [SecretManagement.Keeper.Client]::SetSecret($Name, $Secret, $VaultName).GetAwaiter().GetResult()
    if ($result.IsFailure) {
        Write-Error $result.ErrorMsg
        return
    }
}


function Remove-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    Write-Error "Remove-Secret is not supported for Keeper Vault"
}

function Test-SecretVault
{
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    return [SecretManagement.Keeper.Client]::TestVault($VaultName).GetAwaiter().GetResult()
}
