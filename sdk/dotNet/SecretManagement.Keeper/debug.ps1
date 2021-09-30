Set-Location ./out/SecretManagement.Keeper
Import-Module ./SecretManagement.Keeper.psd1
# Register-KeeperVault -Name K2 -LocalVaultName KeyChain2  
# Register-KeeperVault -Name K1
Get-SecretInfo
# Get-Secret R2
# Register-KeeperVault
# Set-Secret R2.password "456"