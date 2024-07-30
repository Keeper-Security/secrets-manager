function Get-Config {
    param (
        [string] $LocalVaultName
    )
    $vaults = Microsoft.Powershell.SecretManagement\Get-SecretVault
    $localVault = $vaults.Where( { $_.Name -eq $LocalVaultName } ) # SecretStore/LocalStore
    if (!$localVault) {
        return $null
    }

    $moduleInstance = Import-Module -Name $localVault.ModuleName -PassThru
    $configSecretName = 'KeeperVault.' + $VaultName # passed by SecretStore while enumerating registered vaults
    $config = & $moduleInstance Get-Secret -Name $configSecretName -VaultName $localVault.Name
    if ($config -isnot [Hashtable]) {
        $config = $config[0] # SecretStore returns a List
    }
    return $config
}

function Get-Secret {
    [CmdletBinding()]
    param (
        [string] $Name,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    $config = Get-Config -LocalVaultName $AdditionalParameters.LocalVaultName
    if (!$config) {
        Write-Error "Unable to find configuration Vault $($AdditionalParameters.LocalVaultName) for Keeper Vault $($VaultName)"
        return $null
    }
    return [SecretManagement.Keeper.Client]::GetSecret($Name, $config).GetAwaiter().GetResult()
}

function Get-SecretInfo {
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    $config = Get-Config -LocalVaultName $AdditionalParameters.LocalVaultName
    if (!$config) {
        Write-Error "Unable to find configuration Vault $($AdditionalParameters.LocalVaultName) for Keeper Vault $($VaultName)"
        return $null
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
    
    $config = Get-Config -LocalVaultName $AdditionalParameters.LocalVaultName
    if (!$config) {
        Write-Error "Unable to find configuration Vault $($AdditionalParameters.LocalVaultName) for Keeper Vault $($VaultName)"
        return $null
    }

    $result = [SecretManagement.Keeper.Client]::SetSecret($Name, $Secret, $config).GetAwaiter().GetResult()
    if ($result.IsFailure) {
        Write-Error $result.ErrorMessage
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

    if ($Name -eq "ALL") {
        $vaults = Microsoft.Powershell.SecretManagement\Get-SecretVault
        $localVault = $vaults.Where( { $_.Name -eq $AdditionalParameters.LocalVaultName } )
        if ($localVault) {
            $moduleInstance = Import-Module -Name $localVault.ModuleName -PassThru
            $configSecretName = 'KeeperVault.' + $VaultName
            & $moduleInstance Remove-Secret -Name $configSecretName -VaultName $localVault.Name
        }
        $moduleInstance = Import-Module -Name Microsoft.PowerShell.SecretManagement -PassThru
        Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -Name $VaultName
        Write-Host "Keeper Vault $($Name) has been removed"
        return
    }
    
    Write-Error "Remove-Secret is not supported for Keeper Vault"
}

function Test-SecretVault {
    [CmdletBinding()]
    param (
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    
    $config = Get-Config -LocalVaultName $AdditionalParameters.LocalVaultName
    if (!$config) {
        Write-Error "Unable to find configuration Vault $($AdditionalParameters.LocalVaultName) for Keeper Vault $($VaultName)"
        return $null
    }

    return [SecretManagement.Keeper.Client]::TestVault($config).GetAwaiter().GetResult()
}

function Get-Notation {
    [CmdletBinding()]
    param (
        [string] $Config,
        [string] $Notation
    )

    return [SecretManagement.Keeper.Client]::GetNotation($Config, $Notation).GetAwaiter().GetResult()
}
