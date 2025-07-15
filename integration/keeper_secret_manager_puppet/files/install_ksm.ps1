
function Install-Python {
  Write-Host "INFO: Checking if Python3 is installed..."

  $python = Get-Command python3 -ErrorAction SilentlyContinue
  if (-not $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
  }

  if ($python) {
    Write-Host "INFO: Python is installed at $($python.Path)"
    return $true
  }
  
  Write-Host "INFO: Python3 not found. Installing Python3..."

  # Define Python installer URL and local path
  $pythonInstallerUrl = "https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe"
  $installerPath = Join-Path -Path $TmpDir -ChildPath "python-installer.exe"

  try {
    Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $installerPath -UseBasicParsing
  }
  catch {
    Write-Error "Failed to download Python installer: $_"
    return $false
  }

  # Silent install Python with pip and add to PATH for all users
  $installArgs = "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0"
  $process = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -PassThru

  if ($process.ExitCode -ne 0) {
    Write-Error "Python installation failed with exit code $($process.ExitCode)"
    return $false
  }

  Remove-Item $installerPath -Force

  # Verify Python installed
  $python = Get-Command python3 -ErrorAction SilentlyContinue
  if (-not $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
  }

  if ($python) {
    Write-Host "INFO: Python installation successful."
    return $true
  } else {
    Write-Error "Python installation did not complete successfully."
    return $false
  }
}

function Ensure-Pip {
  Write-Host "INFO: Checking if pip3 is installed..."

  $pip = Get-Command pip3 -ErrorAction SilentlyContinue
  if ($pip) {
    Write-Host "INFO: pip3 is already installed."
    return $true
  }

  Write-Host "INFO: pip3 not found. Bootstrapping pip installation..."
  
  $python = Get-Command python3 -ErrorAction SilentlyContinue
  if (-not $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
  }

  if (-not $python) {
    Write-Error "Python is not installed, cannot bootstrap pip."
    return $false
  }

  try {
    # Try to bootstrap pip using ensurepip
    & $python.Path -m ensurepip --upgrade
    Write-Host "INFO: pip3 bootstrapped successfully."
    return $true
  }
  catch {
    Write-Warning "Failed to bootstrap pip via ensurepip: $_"
  }

  try {
    # Try to install pip via get-pip.py as a fallback
    $getPipUrl = "https://bootstrap.pypa.io/get-pip.py"
    $getPipPath = Join-Path -Path $TmpDir -ChildPath "get-pip.py"
    Invoke-WebRequest -Uri $getPipUrl -OutFile $getPipPath -UseBasicParsing

    & $python.Path $getPipPath

    Remove-Item $getPipPath -Force

    Write-Host "INFO: pip3 installed successfully using get-pip.py."
    return $true
  }
  catch {
    Write-Error "Failed to install pip3: $_"
    return $false
  }
}

function Install-PipPackage {
  param([string]$PackageName)

  Write-Host "INFO: Installing $PackageName via pip3..."
  try {
    & pip3 install $PackageName -ErrorAction Stop
    Write-Host "INFO: $PackageName installation successful."
    return $true
  }
  catch {
    Write-Error "$PackageName installation failed: $($_.Exception.Message)"
    return $false
  }
}

function Install-KeeperSecretsManagerCore {
  if (-not (Install-Python)) {
    Write-Error "Python installation failed."
    return $false
  }

  if (-not (Ensure-Pip)) {
    Write-Error "pip3 installation failed."
    return $false
  }

  if (-not (Install-PipPackage "-U keeper-secrets-manager-core")) {
    return $false
  }

  return $true
}

# --- Main Execution Logic ---
if (-not (Install-KeeperSecretsManagerCore)) {
  exit 1
}

exit 0
