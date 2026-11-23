# Local vault modules that only run on macOS. Each one shells out to a macOS-only binary,
# so on Windows and Linux every call into the vault fails.
$script:MacOSOnlyVaultModules = @('SecretManagement.KeyChain')

function Test-KeeperIsMacOS {
  return [bool]$IsMacOS
}

function Get-KeeperVaultConfig {
  param (
    [string] $OneTimeToken,
    [string] $Config
  )
  if ($OneTimeToken) {
    return [SecretManagement.Keeper.Client]::GetVaultConfigFromToken($OneTimeToken).GetAwaiter().GetResult()
  }
  return [SecretManagement.Keeper.Client]::GetVaultConfigFromConfigString($Config).GetAwaiter().GetResult()
}

function Register-KeeperVault {
  [CmdletBinding(DefaultParameterSetName = 'Token')]
  param (
    [Parameter(Mandatory = $true)]
    [string] $Name,
    [Parameter(Mandatory = $true, ParameterSetName = 'Token')]
    [string] $OneTimeToken,
    [Parameter(Mandatory = $true, ParameterSetName = 'Config')]
    [string] $Config,
    [string] $LocalVaultName
  )
  if ($PSVersionTable.PSVersion.Major -lt 6) {
    Write-Error "Keeper Secrets Manager requires PowerShell version 6 or greater - version ($($PSVersionTable.PSVersion.ToString())) is not supported."
    return
  }
  $vaults = Microsoft.Powershell.SecretManagement\Get-SecretVault
  if ($LocalVaultName) {
    $localVaultModuleName = $vaults.Where( { $_.Name -eq $LocalVaultName } ) | Select-Object -ExpandProperty ModuleName
    if (!$localVaultModuleName) {
      Write-Error "Vault $($LocalVaultName) was not found"
      return
    }
  }
  else {
    $localVaultModuleName = 'Microsoft.PowerShell.SecretStore'
    $LocalVaultName = $vaults.Where( { $_.ModuleName -eq $localVaultModuleName } )[0] | Select-Object -ExpandProperty Name
    if (!$LocalVaultName) {
      Write-Error 'Microsoft.PowerShell.SecretStore vault was not found'
      return
    }
  }
  # Check the local vault before redeeming the token: a one-time token can only be used once,
  # so it must not be spent on a vault that cannot store the resulting config.
  if (($localVaultModuleName -in $script:MacOSOnlyVaultModules) -and -not (Test-KeeperIsMacOS)) {
    Write-Error "Vault $($LocalVaultName) uses $($localVaultModuleName), which only works on macOS. Register a Microsoft.PowerShell.SecretStore vault and pass its name to -LocalVaultName."
    return
  }
  if (-not (Microsoft.Powershell.SecretManagement\Test-SecretVault -Name $LocalVaultName -ErrorAction SilentlyContinue)) {
    Write-Error "Vault $($LocalVaultName) ($($localVaultModuleName)) failed Test-SecretVault, so the Keeper Vault config cannot be stored in it. Run Test-SecretVault -Name $($LocalVaultName) to see why."
    return
  }
  $configSecretName = 'KeeperVault.' + $Name
  Write-Host "Storing Keeper Vault config $($configSecretName) in $($localVaultModuleName) Vault named $($LocalVaultName)"
  $moduleInstance = Import-Module -Name $localVaultModuleName -PassThru -ErrorAction Stop
  switch ($PSCmdlet.ParameterSetName) {
    'Token' {
      $result = Get-KeeperVaultConfig -OneTimeToken $OneTimeToken
    }
    'Config' {
      $result = Get-KeeperVaultConfig -Config $Config
    }
  }
  if ($result.IsFailure) {
    Write-Error $result.ErrorMessage
    return
  }
  try {
    & $moduleInstance Set-Secret -Name $configSecretName -Secret $result.Data -VaultName $LocalVaultName -ErrorAction Stop
  }
  catch {
    Write-Error "Could not store Keeper Vault config $($configSecretName) in Vault $($LocalVaultName): $($_.Exception.Message). Keeper Vault $($Name) was not registered."
    return
  }
  $vaultParameters = @{
    LocalVaultName = $LocalVaultName
  }
  Microsoft.Powershell.SecretManagement\Register-SecretVault -Name $Name -ModuleName SecretManagement.Keeper -VaultParameters $vaultParameters
  # for local testing
  # Microsoft.Powershell.SecretManagement\Register-SecretVault -Name $Name -ModuleName ./SecretManagement.Keeper.psd1 -VaultParameters $vaultParameters
}
