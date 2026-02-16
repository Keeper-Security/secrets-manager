# PowerShell Integration Tests for SecretManagement.Keeper
# Tests module import, basic functionality, and dependency compatibility

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Get module path
$ModulePath = Resolve-Path "$PSScriptRoot/../out/SecretManagement.Keeper"
$ManifestPath = Join-Path $ModulePath "SecretManagement.Keeper.psd1"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "PowerShell Integration Tests" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Display environment info
Write-Host "Environment:" -ForegroundColor Yellow
Write-Host "  PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
Write-Host "  OS: $($PSVersionTable.OS)" -ForegroundColor Gray
Write-Host "  Platform: $($PSVersionTable.Platform)" -ForegroundColor Gray
Write-Host "  .NET Version: $([System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)" -ForegroundColor Gray
Write-Host ""

$TestsPassed = 0
$TestsFailed = 0

function Test-Step {
    param(
        [string]$Name,
        [scriptblock]$Test
    )

    Write-Host "TEST: $Name" -ForegroundColor Cyan
    try {
        & $Test
        Write-Host "  ✓ PASSED" -ForegroundColor Green
        $script:TestsPassed++
    }
    catch {
        Write-Host "  ✗ FAILED: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
        $script:TestsFailed++
    }
    Write-Host ""
}

# Test 1: Module manifest exists
Test-Step "Module manifest exists" {
    if (-not (Test-Path $ManifestPath)) {
        throw "Module manifest not found at: $ManifestPath"
    }
}

# Test 2: Module can be imported
Test-Step "Module can be imported" {
    Import-Module $ManifestPath -Force -ErrorAction Stop
}

# Test 3: Module is loaded
Test-Step "Module is loaded" {
    $module = Get-Module -Name SecretManagement.Keeper
    if (-not $module) {
        throw "Module not loaded after import"
    }
    Write-Host "    Module Version: $($module.Version)" -ForegroundColor Gray
}

# Test 4: System.Text.Json version compatibility (KSM-767 guard)
Test-Step "Module ships with compatible System.Text.Json version" {
    # Check the actual DLL file version shipped with the module
    # (not the loaded assembly, which PowerShell substitutes with its own version)
    $jsonDllPath = Join-Path $ModulePath "System.Text.Json.dll"

    if (-not (Test-Path $jsonDllPath)) {
        throw "System.Text.Json.dll not found in module package"
    }

    $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($jsonDllPath)
    $productVersion = $fileVersion.ProductVersion

    # Parse major version (e.g., "9.0.925.41916" -> 9)
    if ($productVersion -match '^(\d+)\.') {
        $majorVersion = [int]$matches[1]
    } else {
        throw "Could not parse System.Text.Json.dll version: $productVersion"
    }

    Write-Host "    System.Text.Json.dll file version: $productVersion" -ForegroundColor Gray

    # PowerShell 7.5 uses System.Text.Json 9.0.0.0
    # Module must ship with 9.x to avoid runtime errors when SDK calls JSON APIs
    # See KSM-767: Upgrading to 10.x causes "Could not load file or assembly" errors
    if ($majorVersion -ne 9) {
        throw @"
System.Text.Json version incompatibility detected!
  Expected: 9.x (PowerShell 7.5 compatibility)
  Found: $productVersion (major version $majorVersion)

This will cause runtime errors when users call SDK methods.
Downgrade System.Text.Json to 9.x in SecretsManager.csproj

Reference: KSM-767 - PowerShell 7.5.4 compatibility issue
"@
    }

    Write-Host "    ✓ Version is compatible with PowerShell 7.4/7.5" -ForegroundColor Gray
}

# Test 5: Module exports expected functions
Test-Step "Module exports expected functions" {
    $commands = Get-Command -Module SecretManagement.Keeper
    $expectedCommands = @('Register-KeeperVault')

    foreach ($cmd in $expectedCommands) {
        if ($cmd -notin $commands.Name) {
            throw "Expected command '$cmd' not found in module exports"
        }
    }

    Write-Host "    Exported commands: $($commands.Count)" -ForegroundColor Gray
}

# Test 6: Extension module is loaded (may be lazy-loaded)
Test-Step "Extension module exists" {
    $extensionPath = Join-Path $ModulePath "SecretManagement.Keeper.Extension"
    if (-not (Test-Path $extensionPath)) {
        throw "Extension module directory not found"
    }
    Write-Host "    Extension path exists: $extensionPath" -ForegroundColor Gray
}

# Test 7: Extension manifest exists
Test-Step "Extension manifest exists" {
    $extensionManifest = Join-Path $ModulePath "SecretManagement.Keeper.Extension/SecretManagement.Keeper.Extension.psd1"
    if (-not (Test-Path $extensionManifest)) {
        throw "Extension manifest not found"
    }

    # Verify it exports the expected functions
    $manifestData = Import-PowerShellDataFile $extensionManifest
    $expectedCommands = @('Get-Secret', 'Set-Secret', 'Remove-Secret', 'Get-SecretInfo', 'Test-SecretVault')
    $exportedFunctions = $manifestData.FunctionsToExport

    foreach ($cmd in $expectedCommands) {
        if ($cmd -notin $exportedFunctions) {
            throw "Expected function '$cmd' not declared in extension manifest"
        }
    }

    Write-Host "    Extension exports: $($exportedFunctions.Count) functions" -ForegroundColor Gray
}

# Test 8: SecretsManager assembly file exists
Test-Step "SecretsManager assembly file exists" {
    $smDll = Join-Path $ModulePath "SecretsManager.dll"
    if (-not (Test-Path $smDll)) {
        throw "SecretsManager.dll not found in module directory"
    }

    # Get version from file
    $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($smDll)
    Write-Host "    SecretsManager.dll Version: $($fileInfo.FileVersion)" -ForegroundColor Gray
}

# Test 9: Required dependency files exist
Test-Step "Required dependency files exist" {
    $requiredDlls = @(
        'BouncyCastle.Cryptography.dll',
        'System.Text.Json.dll',
        'System.Text.Encodings.Web.dll'
    )

    foreach ($dll in $requiredDlls) {
        $dllPath = Join-Path $ModulePath $dll
        if (-not (Test-Path $dllPath)) {
            throw "$dll not found in module directory"
        }
    }

    Write-Host "    All required dependency DLLs present" -ForegroundColor Gray
}

# Test 10: Module can be removed without errors
Test-Step "Module can be removed cleanly" {
    Remove-Module -Name SecretManagement.Keeper -Force -ErrorAction Stop
    Remove-Module -Name SecretManagement.Keeper.Extension -Force -ErrorAction SilentlyContinue
}

# Summary
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Passed: $TestsPassed" -ForegroundColor Green
Write-Host "  Failed: $TestsFailed" -ForegroundColor $(if ($TestsFailed -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Total:  $($TestsPassed + $TestsFailed)" -ForegroundColor Gray
Write-Host ""

if ($TestsFailed -gt 0) {
    Write-Host "RESULT: FAILED" -ForegroundColor Red
    exit 1
}
else {
    Write-Host "RESULT: PASSED" -ForegroundColor Green
    exit 0
}
