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
        './bin/Release/netstandard2.0/SecretsManager.dll'
        './bin/Release/netstandard2.0/SecretManagement.Keeper.dll'
        './bin/Release/netstandard2.0/SecretManagement.Keeper.deps.json'
        './bin/Release/netstandard2.0/BouncyCastle.Cryptography.dll'
        './bin/Release/netstandard2.0/Microsoft.Bcl.AsyncInterfaces.dll'
        './bin/Release/netstandard2.0/System.Buffers.dll'
        './bin/Release/netstandard2.0/System.Management.Automation.dll'
        './bin/Release/netstandard2.0/System.Memory.dll'
        './bin/Release/netstandard2.0/System.Numerics.Vectors.dll'
        './bin/Release/netstandard2.0/System.Runtime.CompilerServices.Unsafe.dll'
        './bin/Release/netstandard2.0/System.Text.Encodings.Web.dll'
        './bin/Release/netstandard2.0/System.Text.Json.dll'
        './bin/Release/netstandard2.0/System.Threading.Tasks.Extensions.dll'
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
