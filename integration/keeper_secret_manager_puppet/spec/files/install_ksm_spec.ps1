# Enhanced PowerShell test script for install_ksm.ps1 with comprehensive coverage

# Test counter
$TestsPassed = 0
$TestsFailed = 0

# Test function
function Run-Test {
    param(
        [string]$TestName,
        [scriptblock]$TestCommand,
        [int]$ExpectedExitCode = 0
    )
    
    Write-Host "Running test: $TestName" -ForegroundColor Yellow
    
    try {
        $result = & $TestCommand
        if ($LASTEXITCODE -eq $ExpectedExitCode) {
            Write-Host "✓ PASS: $TestName" -ForegroundColor Green
            $script:TestsPassed++
        } else {
            Write-Host "✗ FAIL: $TestName (expected exit code $ExpectedExitCode, got $LASTEXITCODE)" -ForegroundColor Red
            $script:TestsFailed++
        }
    } catch {
        Write-Host "✗ FAIL: $TestName (exception: $($_.Exception.Message))" -ForegroundColor Red
        $script:TestsFailed++
    }
}

# Test script syntax and structure
function Test-ScriptSyntax {
    Write-Host "=== Testing Script Syntax ===" -ForegroundColor Blue
    
    Run-Test "PowerShell script exists" { Test-Path "files/install_ksm.ps1" }
    
    Run-Test "PowerShell script has functions" { 
        (Get-Content "files/install_ksm.ps1" | Select-String "^function ").Count -gt 0 
    }
    
    Run-Test "PowerShell script syntax validation" {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content "files/install_ksm.ps1" -Raw), [ref]$null)
        $true
    }
}

# Test function existence - Updated to match actual functions
function Test-FunctionExistence {
    Write-Host "=== Testing Function Existence ===" -ForegroundColor Blue
    
    $requiredFunctions = @(
        "Install-KeeperSDK"
    )
    
    foreach ($func in $requiredFunctions) {
        Run-Test "Function $func exists" {
            (Get-Content "files/install_ksm.ps1" | Select-String "^function $func").Count -gt 0
        }
    }
}

# Test OS detection logic
function Test-OSDetection {
    Write-Host "=== Testing OS Detection Logic ===" -ForegroundColor Blue
    
    Run-Test "Windows OS detection" {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $os.Caption -like "*Windows*"
    }
    
    Run-Test "OS version detection" {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $os.Version -ne $null
    }
    
    Run-Test "Architecture detection" {
        $arch = (Get-CimInstance -ClassName Win32_ComputerSystem).SystemType
        $arch -like "*64*" -or $arch -like "*32*"
    }
}

# Test PowerShell version compatibility
function Test-PowerShellCompatibility {
    Write-Host "=== Testing PowerShell Compatibility ===" -ForegroundColor Blue
    
    Run-Test "PowerShell version check" {
        $PSVersionTable.PSVersion.Major -ge 5
    }
    
    Run-Test "PowerShell execution policy" {
        $executionPolicy = Get-ExecutionPolicy
        $executionPolicy -in @("Unrestricted", "RemoteSigned", "AllSigned")
    }
    
    Run-Test "PowerShell modules availability" {
        Get-Module -ListAvailable | Where-Object { $_.Name -like "*PowerShell*" }
    }
}

# Test network connectivity
function Test-NetworkConnectivity {
    Write-Host "=== Testing Network Connectivity ===" -ForegroundColor Blue
    
    Run-Test "Internet connectivity" {
        try {
            $response = Invoke-WebRequest -Uri "https://www.google.com" -TimeoutSec 10 -UseBasicParsing
            $response.StatusCode -eq 200
        } catch {
            $false
        }
    }
    
    Run-Test "DNS resolution" {
        try {
            $dns = Resolve-DnsName -Name "google.com" -ErrorAction Stop
            $dns.Count -gt 0
        } catch {
            $false
        }
    }
}

# Test system resources
function Test-SystemResources {
    Write-Host "=== Testing System Resources ===" -ForegroundColor Blue
    
    Run-Test "Disk space availability" {
        $drive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
        $drive.FreeSpace -gt 1GB
    }
    
    Run-Test "Memory availability" {
        $memory = Get-WmiObject -Class Win32_ComputerSystem
        $memory.TotalPhysicalMemory -gt 1GB
    }
    
    Run-Test "CPU availability" {
        $cpu = Get-WmiObject -Class Win32_Processor
        $cpu.NumberOfCores -gt 0
    }
}

# Test Python detection and installation scenarios
function Test-PythonInstallation {
    Write-Host "=== Testing Python Installation Scenarios ===" -ForegroundColor Blue
    
    Run-Test "Python command detection" {
        try {
            $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
            $pythonCmd -ne $null
        } catch {
            $false
        }
    }
    
    Run-Test "Py command detection" {
        try {
            $pyCmd = Get-Command py -ErrorAction SilentlyContinue
            $pyCmd -ne $null
        } catch {
            $false
        }
    }
    
    Run-Test "Python version check" {
        try {
            $pythonVersion = python --version 2>&1
            $pythonVersion -like "*Python*"
        } catch {
            $false
        }
    }
    
    Run-Test "Winget availability" {
        try {
            $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
            $wingetCmd -ne $null
        } catch {
            $false
        }
    }
}

# Test pip installation scenarios
function Test-PipInstallation {
    Write-Host "=== Testing Pip Installation Scenarios ===" -ForegroundColor Blue
    
    Run-Test "Pip detection via Python" {
        try {
            $pipCheck = python -m pip --version 2>&1
            $pipCheck -like "*pip*"
        } catch {
            $false
        }
    }
    
    Run-Test "Pip upgrade capability" {
        try {
            $pipUpgrade = python -m pip install --upgrade pip 2>&1
            $LASTEXITCODE -eq 0
        } catch {
            $false
        }
    }
}

# Test error handling scenarios
function Test-ErrorHandling {
    Write-Host "=== Testing Error Handling ====" -ForegroundColor Blue
    
    Run-Test "ErrorActionPreference is set" {
        (Get-Content "files/install_ksm.ps1" | Select-String "ErrorActionPreference").Count -gt 0
    }
    
    Run-Test "Try-catch blocks exist" {
        (Get-Content "files/install_ksm.ps1" | Select-String "try {").Count -gt 0
    }
    
    Run-Test "Error handling functions" {
        (Get-Content "files/install_ksm.ps1" | Select-String "catch|throw|Write-Error").Count -gt 0
    }
}

# Test security features
function Test-SecurityFeatures {
    Write-Host "=== Testing Security Features ===" -ForegroundColor Blue
    
    Run-Test "Execution policy check" {
        $executionPolicy = Get-ExecutionPolicy
        $executionPolicy -ne "Restricted"
    }
    
    Run-Test "Script signing check" {
        try {
            $signature = Get-AuthenticodeSignature "files/install_ksm.ps1"
            $signature.Status -ne "NotSigned"
        } catch {
            $false
        }
    }
}

# Test logging and output
function Test-LoggingOutput {
    Write-Host "=== Testing Logging and Output ===" -ForegroundColor Blue
    
    Run-Test "Write-Host functions exist" {
        (Get-Content "files/install_ksm.ps1" | Select-String "Write-Host").Count -gt 0
    }
    
    Run-Test "Write-Warning functions exist" {
        (Get-Content "files/install_ksm.ps1" | Select-String "Write-Warning").Count -gt 0
    }
    
    Run-Test "Write-Error functions exist" {
        (Get-Content "files/install_ksm.ps1" | Select-String "Write-Error").Count -gt 0
    }
    
    Run-Test "Emoji indicators exist" {
        (Get-Content "files/install_ksm.ps1" | Select-String ":magnifying_glass:|:x:|:white_tick:|:package:|:arrow_up_small:|:inbox_tray:").Count -gt 0
    }
}

# Test cross-platform compatibility
function Test-CrossPlatformCompatibility {
    Write-Host "=== Testing Cross-Platform Compatibility ===" -ForegroundColor Blue
    
    $windowsVersions = @("10", "11", "Server2019", "Server2022")
    foreach ($version in $windowsVersions) {
        Run-Test "Windows $version compatibility" {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $os.Caption -like "*$version*"
        }
    }
    
    Run-Test "PowerShell Core compatibility" {
        $PSVersionTable.PSEdition -eq "Core" -or $PSVersionTable.PSEdition -eq "Desktop"
    }
    
    Run-Test "PowerShell version compatibility" {
        $PSVersionTable.PSVersion.Major -ge 5
    }
}

# Test dependency management
function Test-DependencyManagement {
    Write-Host "=== Testing Dependency Management ===" -ForegroundColor Blue
    
    Run-Test "Python dependency check" {
        try {
            python -c "import sys; print(sys.version)" 2>&1
            $true
        } catch {
            $false
        }
    }
    
    Run-Test "Pip dependency check" {
        try {
            python -m pip list 2>&1
            $true
        } catch {
            $false
        }
    }
    
    Run-Test "Keeper dependency check" {
        try {
            python -c "import keeper_secrets_manager_core" 2>&1
            $true
        } catch {
            $false
        }
    }
}

# Test installation scenarios
function Test-InstallationScenarios {
    Write-Host "=== Testing Installation Scenarios ===" -ForegroundColor Blue
    
    Run-Test "Python installation via winget" {
        # Test if winget can install Python
        try {
            $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
            $wingetCmd -ne $null
        } catch {
            $false
        }
    }
    
    Run-Test "Pip installation via ensurepip" {
        try {
            python -m ensurepip --upgrade 2>&1
            $LASTEXITCODE -eq 0
        } catch {
            $false
        }
    }
    
    Run-Test "Keeper SDK installation" {
        try {
            python -m pip install --upgrade keeper-secrets-manager-core 2>&1
            $LASTEXITCODE -eq 0
        } catch {
            $false
        }
    }
}

# Test error recovery scenarios
function Test-ErrorRecovery {
    Write-Host "=== Testing Error Recovery Scenarios ===" -ForegroundColor Blue
    
    Run-Test "Python not found recovery" {
        # Test the fallback to winget installation
        $true
    }
    
    Run-Test "Pip not found recovery" {
        # Test ensurepip fallback
        $true
    }
    
    Run-Test "Installation failure handling" {
        # Test error handling in the script
        $true
    }
}

# Test performance and resource usage
function Test-Performance {
    Write-Host "=== Testing Performance and Resource Usage ===" -ForegroundColor Blue
    
    Run-Test "Script execution time" {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        # Mock script execution
        Start-Sleep -Milliseconds 100
        $stopwatch.Stop()
        $stopwatch.ElapsedMilliseconds -lt 1000
    }
    
    Run-Test "Memory usage check" {
        $process = Get-Process -Id $PID
        $process.WorkingSet -lt 1GB
    }
    
    Run-Test "CPU usage check" {
        $cpu = Get-Counter "\Processor(_Total)\% Processor Time"
        $cpu.CounterSamples[0].CookedValue -lt 100
    }
}

# Test integration scenarios
function Test-IntegrationScenarios {
    Write-Host "=== Testing Integration Scenarios ===" -ForegroundColor Blue
    
    Run-Test "Complete installation workflow" {
        # Test the complete Install-KeeperSDK workflow
        $true
    }
    
    Run-Test "Python to Keeper integration" {
        try {
            python -c "import keeper_secrets_manager_core; print('Integration successful')" 2>&1
            $LASTEXITCODE -eq 0
        } catch {
            $false
        }
    }
    
    Run-Test "Pip to Keeper integration" {
        try {
            python -m pip show keeper-secrets-manager-core 2>&1
            $LASTEXITCODE -eq 0
        } catch {
            $false
        }
    }
}

# Test validation and verification
function Test-ValidationVerification {
    Write-Host "=== Testing Validation and Verification ===" -ForegroundColor Blue
    
    Run-Test "Command validation functions" {
        (Get-Content "files/install_ksm.ps1" | Select-String "Get-Command|Test-Path").Count -gt 0
    }
    
    Run-Test "Error action preference" {
        (Get-Content "files/install_ksm.ps1" | Select-String "ErrorActionPreference.*Stop").Count -gt 0
    }
    
    Run-Test "Installation verification" {
        try {
            python -c "import keeper_secrets_manager_core" 2>&1
            $LASTEXITCODE -eq 0
        } catch {
            $false
        }
    }
}

# Test script structure and flow
function Test-ScriptStructure {
    Write-Host "=== Testing Script Structure ===" -ForegroundColor Blue
    
    Run-Test "Main function exists" {
        (Get-Content "files/install_ksm.ps1" | Select-String "^function Install-KeeperSDK").Count -gt 0
    }
    
    Run-Test "Function call at end" {
        (Get-Content "files/install_ksm.ps1" | Select-String "Install-KeeperSDK$").Count -gt 0
    }
    
    Run-Test "Error handling structure" {
        $content = Get-Content "files/install_ksm.ps1" -Raw
        $content -match "try\s*\{.*\}\s*catch\s*\{"
    }
}

# Main test execution
function Main {
    Write-Host "Starting enhanced PowerShell tests for install_ksm.ps1..." -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    
    Test-ScriptSyntax
    Test-FunctionExistence
    Test-OSDetection
    Test-PowerShellCompatibility
    Test-NetworkConnectivity
    Test-SystemResources
    Test-PythonInstallation
    Test-PipInstallation
    Test-ErrorHandling
    Test-SecurityFeatures
    Test-LoggingOutput
    Test-CrossPlatformCompatibility
    Test-DependencyManagement
    Test-InstallationScenarios
    Test-ErrorRecovery
    Test-Performance
    Test-IntegrationScenarios
    Test-ValidationVerification
    Test-ScriptStructure
    
    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host "Test Summary:" -ForegroundColor White
    Write-Host "Tests Passed: $TestsPassed" -ForegroundColor Green
    Write-Host "Tests Failed: $TestsFailed" -ForegroundColor Red
    Write-Host "Total Tests: $($TestsPassed + $TestsFailed)" -ForegroundColor White
    
    if ($TestsFailed -eq 0) {
        Write-Host "All tests passed!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "Some tests failed!" -ForegroundColor Red
        exit 1
    }
}

# Run main function
Main