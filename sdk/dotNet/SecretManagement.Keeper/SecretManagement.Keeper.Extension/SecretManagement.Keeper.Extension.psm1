function Get-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $configSecretName = 'KeeperVault.' + $VaultName
    $moduleName = 'Microsoft.PowerShell.SecretStore'
    $moduleInstance = Import-Module -Name $moduleName -PassThru
    $config = & $moduleInstance Get-Secret -Name $configSecretName
    return [SecretManagement.Keeper.Client]::GetSecret($Name, $config[0]).GetAwaiter().GetResult()
}

function Get-SecretInfo {
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    $vaults = Microsoft.Powershell.SecretManagement\Get-SecretVault
    $localVault = $vaults.Where( { $_.Name -eq $AdditionalParameters.LocalVaultName } )
    if (!$localVault) {
        Write-Error "Unable to find configuration Vault $($AdditionalParameters.LocalVaultName) for Keeper Vault $($VaultName)"
    }
    $moduleInstance = Import-Module -Name $localVault.ModuleName -PassThru
    $configSecretName = 'KeeperVault.' + $VaultName
    $config = & $moduleInstance Get-Secret -Name $configSecretName -VaultName $localVault.Name
    if ($config -isnot [Hashtable]) { 
        $config = $config[0] # SecretStore returns a List
    }
    $secrets = [SecretManagement.Keeper.Client]::GetSecretsInfo($Filter, $config).GetAwaiter().GetResult()

    $secretsInfo = New-Object System.Collections.Generic.List[System.Object]
    foreach ($secret in $secrets) {
        $secretsInfo.Add([Microsoft.PowerShell.SecretManagement.SecretInformation]::new($secret, "Hashtable", $VaultName, $Metadata))                  
    }
    return $secretsInfo
}

function Set-Secret {
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


function Remove-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    Write-Error "Remove-Secret is not supported for Keeper Vault"
}

function Test-SecretVault {
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    return [SecretManagement.Keeper.Client]::TestVault($VaultName).GetAwaiter().GetResult()
}
