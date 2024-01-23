[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $Package,

    [Parameter()]
    [switch]
    $Publish,

    [Parameter()]
    $APIKey
)

Push-Location $PSScriptRoot

if ($Package) {
    $outDir = Join-Path 'out' 'SecretManagement.Keeper'
    Remove-Item out -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

    @(
        'SecretManagement.Keeper.Extension'
        'SecretManagement.Keeper.psd1'
        'SecretManagement.Keeper.psm1'
        'README.md'
    ) | ForEach-Object {
        Copy-Item -Path $_ -Destination (Join-Path $outDir $_) -Force -Recurse
    }

    @(
        './bin/Release/netstandard2.1/SecretManagement.Keeper.dll'
        './bin/Release/netstandard2.1/SecretsManager.dll'
        './bin/Release/netstandard2.1/BouncyCastle.Cryptography.dll'
    ) | ForEach-Object {
        Copy-Item -Path $_ -Destination $outDir -Force
    }

    Copy-Item -Path '../../../LICENSE' -Destination $outDir -Force
}

if ($Publish) {
    if (!$APIKey) {
        $APIKey = Read-Host 'API Key'
    }
    Publish-Module -Path ./out/SecretManagement.Keeper -NuGetApiKey $APIKey -Verbose
}

Pop-Location