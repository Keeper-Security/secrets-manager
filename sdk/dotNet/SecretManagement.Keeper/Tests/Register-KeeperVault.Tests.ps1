# Pester unit tests for Register-KeeperVault.
# SecretManagement cmdlets and token redemption are mocked: no vault is touched and no network call is made.
#
# Run: Invoke-Pester ./SecretManagement.Keeper/Tests/Register-KeeperVault.Tests.ps1

BeforeAll {
    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
    Import-Module (Join-Path $PSScriptRoot '../SecretManagement.Keeper.psm1') -Force -ErrorAction Stop

    # Stands in for the local vault module that Register-KeeperVault imports and calls Set-Secret on.
    function New-FakeLocalVaultModule {
        param ([switch] $SetSecretFails)
        New-Module -Name FakeLocalVault -ArgumentList $SetSecretFails.IsPresent -ScriptBlock {
            param ($fail)
            $script:Fail = $fail
            $script:Calls = [System.Collections.Generic.List[hashtable]]::new()
            function Set-Secret {
                [CmdletBinding()]
                param ($Name, $Secret, $VaultName)
                $script:Calls.Add(@{ Name = $Name; VaultName = $VaultName })
                if ($script:Fail) { throw 'disk full' }
            }
            function Get-Calls { $script:Calls.ToArray() }
        }
    }

    function Set-LocalVault {
        param ([string] $Name, [string] $ModuleName)
        $vault = [pscustomobject]@{ Name = $Name; ModuleName = $ModuleName }
        Mock -ModuleName SecretManagement.Keeper Get-SecretVault { $vault }.GetNewClosure()
    }
}

AfterAll {
    Remove-Module SecretManagement.Keeper -Force -ErrorAction SilentlyContinue
}

Describe 'Register-KeeperVault' {
    BeforeEach {
        $script:fakeModule = New-FakeLocalVaultModule
        $fake = $script:fakeModule
        Mock -ModuleName SecretManagement.Keeper Import-Module { $fake }.GetNewClosure()
        Mock -ModuleName SecretManagement.Keeper Test-SecretVault { $true }
        Mock -ModuleName SecretManagement.Keeper Register-SecretVault { }
        Mock -ModuleName SecretManagement.Keeper Get-KeeperVaultConfig {
            [pscustomobject]@{ IsFailure = $false; Data = @{ clientId = 'x' }; ErrorMessage = $null }
        }
        Mock -ModuleName SecretManagement.Keeper Test-KeeperIsMacOS { $false }
        Mock -ModuleName SecretManagement.Keeper Write-Host { }
    }

    Context 'local vault is macOS-only (SecretManagement.KeyChain)' {
        BeforeEach { Set-LocalVault -Name LocalKeeperStore -ModuleName SecretManagement.KeyChain }

        It 'fails before redeeming the token when not on macOS' {
            $err = $null
            Register-KeeperVault -Name Keeper -LocalVaultName LocalKeeperStore -OneTimeToken 'US:TOKEN' -ErrorVariable err -ErrorAction SilentlyContinue

            $err | Should -HaveCount 1
            "$($err[0])" | Should -BeLike '*SecretManagement.KeyChain*only works on macOS*Microsoft.PowerShell.SecretStore*'
            Should -Invoke -ModuleName SecretManagement.Keeper Get-KeeperVaultConfig -Times 0 -Exactly
            Should -Invoke -ModuleName SecretManagement.Keeper Test-SecretVault -Times 0 -Exactly
            Should -Invoke -ModuleName SecretManagement.Keeper Register-SecretVault -Times 0 -Exactly
        }

        It 'is allowed on macOS' {
            Mock -ModuleName SecretManagement.Keeper Test-KeeperIsMacOS { $true }

            Register-KeeperVault -Name Keeper -LocalVaultName LocalKeeperStore -OneTimeToken 'US:TOKEN' -ErrorAction Stop

            Should -Invoke -ModuleName SecretManagement.Keeper Get-KeeperVaultConfig -Times 1 -Exactly
            Should -Invoke -ModuleName SecretManagement.Keeper Register-SecretVault -Times 1 -Exactly
        }
    }

    Context 'local vault fails Test-SecretVault' {
        BeforeEach {
            Set-LocalVault -Name LocalStore -ModuleName Microsoft.PowerShell.SecretStore
            Mock -ModuleName SecretManagement.Keeper Test-SecretVault { $false }
        }

        It 'fails before redeeming the token' {
            $err = $null
            Register-KeeperVault -Name Keeper -LocalVaultName LocalStore -OneTimeToken 'US:TOKEN' -ErrorVariable err -ErrorAction SilentlyContinue

            $err | Should -HaveCount 1
            "$($err[0])" | Should -BeLike '*LocalStore*failed Test-SecretVault*'
            Should -Invoke -ModuleName SecretManagement.Keeper Test-SecretVault -Times 1 -Exactly -ParameterFilter { $Name -eq 'LocalStore' }
            Should -Invoke -ModuleName SecretManagement.Keeper Get-KeeperVaultConfig -Times 0 -Exactly
            Should -Invoke -ModuleName SecretManagement.Keeper Register-SecretVault -Times 0 -Exactly
        }
    }

    Context 'storing the config in the local vault fails' {
        BeforeEach {
            Set-LocalVault -Name LocalStore -ModuleName Microsoft.PowerShell.SecretStore
            $script:fakeModule = New-FakeLocalVaultModule -SetSecretFails
            $fake = $script:fakeModule
            Mock -ModuleName SecretManagement.Keeper Import-Module { $fake }.GetNewClosure()
        }

        It 'writes an error and does not register the Keeper vault' {
            $err = $null
            Register-KeeperVault -Name Keeper -LocalVaultName LocalStore -OneTimeToken 'US:TOKEN' -ErrorVariable err -ErrorAction SilentlyContinue

            # -ErrorVariable also collects the Set-Secret error that Register-KeeperVault catches; ours is last.
            "$($err[-1])" | Should -BeLike '*Could not store Keeper Vault config KeeperVault.Keeper in Vault LocalStore*disk full*was not registered*'
            Should -Invoke -ModuleName SecretManagement.Keeper Register-SecretVault -Times 0 -Exactly
        }
    }

    Context 'token redemption fails' {
        BeforeEach {
            Set-LocalVault -Name LocalStore -ModuleName Microsoft.PowerShell.SecretStore
            Mock -ModuleName SecretManagement.Keeper Get-KeeperVaultConfig {
                [pscustomobject]@{ IsFailure = $true; Data = 'access_denied'; ErrorMessage = 'access_denied' }
            }
        }

        It 'writes the error and stores nothing' {
            $err = $null
            Register-KeeperVault -Name Keeper -LocalVaultName LocalStore -OneTimeToken 'US:TOKEN' -ErrorVariable err -ErrorAction SilentlyContinue

            "$($err[0])" | Should -Be 'access_denied'
            @(& $script:fakeModule Get-Calls) | Should -HaveCount 0
            Should -Invoke -ModuleName SecretManagement.Keeper Register-SecretVault -Times 0 -Exactly
        }
    }

    Context 'working local vault' {
        BeforeEach { Set-LocalVault -Name LocalStore -ModuleName Microsoft.PowerShell.SecretStore }

        It 'stores the config and registers the Keeper vault (token)' {
            Register-KeeperVault -Name Keeper -LocalVaultName LocalStore -OneTimeToken 'US:TOKEN' -ErrorAction Stop

            Should -Invoke -ModuleName SecretManagement.Keeper Get-KeeperVaultConfig -Times 1 -Exactly -ParameterFilter { $OneTimeToken -eq 'US:TOKEN' }
            $calls = @(& $script:fakeModule Get-Calls)
            $calls | Should -HaveCount 1
            $calls[0] | Should -BeOfType [hashtable]
            $calls[0].Name | Should -Be 'KeeperVault.Keeper'
            $calls[0].VaultName | Should -Be 'LocalStore'
            Should -Invoke -ModuleName SecretManagement.Keeper Register-SecretVault -Times 1 -Exactly -ParameterFilter {
                $Name -eq 'Keeper' -and $ModuleName -eq 'SecretManagement.Keeper' -and $VaultParameters.LocalVaultName -eq 'LocalStore'
            }
        }

        It 'passes a config string through to redemption (config)' {
            Register-KeeperVault -Name Keeper -LocalVaultName LocalStore -Config 'BASE64CONFIG' -ErrorAction Stop

            Should -Invoke -ModuleName SecretManagement.Keeper Get-KeeperVaultConfig -Times 1 -Exactly -ParameterFilter { $Config -eq 'BASE64CONFIG' }
            Should -Invoke -ModuleName SecretManagement.Keeper Register-SecretVault -Times 1 -Exactly
        }

        It 'defaults to the first SecretStore vault when -LocalVaultName is omitted' {
            Register-KeeperVault -Name Keeper -OneTimeToken 'US:TOKEN' -ErrorAction Stop

            Should -Invoke -ModuleName SecretManagement.Keeper Test-SecretVault -Times 1 -Exactly -ParameterFilter { $Name -eq 'LocalStore' }
            Should -Invoke -ModuleName SecretManagement.Keeper Register-SecretVault -Times 1 -Exactly
        }
    }

    Context 'local vault lookup' {
        It 'errors when the named vault does not exist' {
            Set-LocalVault -Name Other -ModuleName Microsoft.PowerShell.SecretStore
            $err = $null
            Register-KeeperVault -Name Keeper -LocalVaultName Missing -OneTimeToken 'US:TOKEN' -ErrorVariable err -ErrorAction SilentlyContinue

            "$($err[0])" | Should -Be 'Vault Missing was not found'
            Should -Invoke -ModuleName SecretManagement.Keeper Get-KeeperVaultConfig -Times 0 -Exactly
        }
    }
}
