function Get-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    return [SecretManagement.Keeper.Client]::GetSecret($Name, $VaultName, $AdditionalParameters).GetAwaiter().GetResult()
}

function Get-SecretInfo
{
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    $secrets = [SecretManagement.Keeper.Client]::GetSecretsInfo($Filter, $VaultName, $AdditionalParameters).GetAwaiter().GetResult()
    
    Write-Host "Here too"
    
    $secretsInfo = New-Object System.Collections.Generic.List[System.Object]
    foreach ($secret in $secrets) {
        $secretInfo = [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                          $secret,      # Name of secret
                          "String",      # Secret data type [Microsoft.PowerShell.SecretManagement.SecretType]
                          $VaultName,    # Name of vault
                          $Metadata)
        $secretsInfo.Add($secretInfo)                  
    }
    return $secretsInfo
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
    
    Write-Host "Set-Secret"

    [TestStore]::SetItem($Name, $Secret)
}


function Remove-Secret
{
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    Write-Host "Remove-Secret"

    [TestStore]::RemoveItem($Name)
}

function Test-SecretVault
{
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    Write-Host "Test-SecretVault"

    return [TestStore]::TestVault()
}
