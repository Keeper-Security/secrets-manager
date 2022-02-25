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
  if (($PSVersionTable.PSVersion.Major -lt 5) -or (($PSVersionTable.PSVersion.Major -eq 5) -and ($PSVersionTable.PSVersion.Minor -eq 0))) {
    Write-Error "Keeper Secrets Manager: this version of Powershell ($($PSVersionTable.PSVersion.ToString())) is not supported"
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
  $configSecretName = 'KeeperVault.' + $Name
  Write-Host "Storing Keeper Vault config $($configSecretName) in $($localVaultModuleName) Vault named $($LocalVaultName)"
  $moduleInstance = Import-Module -Name $localVaultModuleName -PassThru -ErrorAction Stop
  switch ($PSCmdlet.ParameterSetName) {
    'Token' {
      $result = [SecretManagement.Keeper.Client]::GetVaultConfigFromToken($OneTimeToken).GetAwaiter().GetResult()
    }
    'Config' {
      $result = [SecretManagement.Keeper.Client]::GetVaultConfigFromConfigString($Config).GetAwaiter().GetResult()
    }
  }
  if ($result.IsFailure) {
    Write-Error $result.ErrorMessage 
    return
  }
  & $moduleInstance Set-Secret -Name $configSecretName -Secret $result.Data -VaultName $LocalVaultName  
  $vaultParameters = @{
    LocalVaultName = $LocalVaultName
  }
  Microsoft.Powershell.SecretManagement\Register-SecretVault -Name $Name -ModuleName SecretManagement.Keeper -VaultParameters $vaultParameters
  # for local testing
  # Microsoft.Powershell.SecretManagement\Register-SecretVault -Name $Name -ModuleName ./SecretManagement.Keeper.psd1 -VaultParameters $vaultParameters
}