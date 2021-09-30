function Register-KeeperVault {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string] $Name,
    [Parameter(Mandatory = $true)]
    [string] $OneTimeToken,
    [string] $LocalVaultName
  )
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
  $result = [SecretManagement.Keeper.Client]::GetVaultConfig($OneTimeToken).GetAwaiter().GetResult()
  if ($result.IsFailure) {
    Write-Error $result.ErrorMessage 
    return
  }
  & $moduleInstance Set-Secret -Name $configSecretName -Secret $result.Data -VaultName $LocalVaultName  
  $vaultParameters = @{
    LocalVaultName = $LocalVaultName
  }
  Microsoft.Powershell.SecretManagement\Register-SecretVault -Name $Name -ModuleName SecretManagement.Keeper -VaultParameters $vaultParameters
}