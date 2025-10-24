# Stop on errors
$ErrorActionPreference = "Stop"
function Install-KeeperSDK {
    try {
        Write-Host "`n:magnifying_glass: Checking for Python..."
        # Find python or py
        if (Get-Command python -ErrorAction SilentlyContinue) {
            $pythonCmd = "python"
        } elseif (Get-Command py -ErrorAction SilentlyContinue) {
            $pythonCmd = "py"
        } else {
            Write-Warning ":x: Python not found. Trying winget..."
            # Check if winget is available
            if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
                Write-Error ":x: Winget is not available. Install Python manually."
                return
            }
            # Install Python silently
            winget install --id Python.Python.3 --silent --accept-source-agreements --accept-package-agreements
            Start-Sleep -Seconds 5
            # Try again to detect
            if (Get-Command python -ErrorAction SilentlyContinue) {
                $pythonCmd = "python"
            } elseif (Get-Command py -ErrorAction SilentlyContinue) {
                $pythonCmd = "py"
            } else {
                Write-Error ":x: Python still not detected after install."
                return
            }
        }
        Write-Host ":white_tick: Using Python: $pythonCmd"
        # Check pip
        $pipCheck = & $pythonCmd -m pip --version 2>$null
        if (-not $pipCheck) {
            Write-Host ":package: pip not found. Installing..."
            & $pythonCmd -m ensurepip --upgrade
        }
        # Upgrade pip
        Write-Host ":arrow_up_small: Upgrading pip..."
        & $pythonCmd -m pip install --upgrade pip
        # Install SDK
        Write-Host ":inbox_tray: Installing keeper-secrets-manager-core..."
        & $pythonCmd -m pip install --upgrade keeper-secrets-manager-core
        Write-Host "`n:white_tick: Installation complete."
    }
    catch {
        Write-Host "`n:x: ERROR: $($_.Exception.Message)"
    }
}
Install-KeeperSDK