#!/bin/bash
set -euo pipefail

install_pip3() {
  echo "INFO: pip3 command not found. Attempting to install pip3..."

  # Detect OS type
  OS_TYPE="$(uname -s)"

  if [[ "$OS_TYPE" == "Linux" ]]; then
    install_python_linux
  elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # macOS logic with comprehensive fallback
    install_python_macos
  elif [[ "$OS_TYPE" == "MINGW"* ]] || [[ "$OS_TYPE" == "MSYS"* ]] || [[ "$OS_TYPE" == "CYGWIN"* ]]; then
    # Windows via Git Bash, MSYS2, or Cygwin
    install_python_windows
  else
    echo "ERROR: Unsupported OS: $OS_TYPE"
    return 1
  fi

  # Verify pip3 installation
  if ! command -v pip3 &> /dev/null; then
    echo "ERROR: pip3 installation failed."
    return 1
  fi

  echo "INFO: pip3 installation successful."
  return 0
}

install_python_linux() {
  echo "INFO: Installing Python on Linux..."
  
  if command -v apt-get &> /dev/null; then
    echo "INFO: Detected apt-get package manager. Installing python3-pip..."
    apt-get update
    apt-get install -y python3-pip
      
    # Upgrade Python3 to latest version
    echo "INFO: Upgrading Python3 to latest version..."
    python3 -m pip install --upgrade pip
    python3 -m pip install --upgrade python3
      
  elif command -v yum &> /dev/null; then
    echo "INFO: Detected yum package manager. Installing python3-pip..."
    yum install -y python3-pip
      
    # Upgrade Python3 to latest version
    echo "INFO: Upgrading Python3 to latest version..."
    python3 -m pip install --upgrade pip
    python3 -m pip install --upgrade python3
      
  elif command -v dnf &> /dev/null; then
    echo "INFO: Detected dnf package manager. Installing python3-pip..."
    dnf install -y python3-pip
      
    # Upgrade Python3 to latest version
    echo "INFO: Upgrading Python3 to latest version..."
    python3 -m pip install --upgrade pip
    python3 -m pip install --upgrade python3
      
  else
    echo "ERROR: Could not detect package manager to install pip3. Please install it manually."
    return 1
  fi
}


install_python_macos() {
  echo "INFO: Installing Python on macOS with fallback options..."

  # Method 1: Try Homebrew (preferred)
  if install_python_via_homebrew; then
    echo "INFO: Python installed successfully via Homebrew."
    return 0
  fi

  # Method 2: Try system Python (if available)
  if install_python_via_system; then
    echo "INFO: Python installed successfully via system package."
    return 0
  fi

  # Method 3: Try pyenv
  if install_python_via_pyenv; then
    echo "INFO: Python installed successfully via pyenv."
    return 0
  fi

  # Method 4: Try direct download
  if install_python_via_download; then
    echo "INFO: Python installed successfully via direct download."
    return 0
  fi

  # Method 5: Try conda/miniconda
  if install_python_via_conda; then
    echo "INFO: Python installed successfully via conda."
    return 0
  fi

  echo "ERROR: All Python installation methods failed."
  return 1
}

install_python_via_homebrew() {
  echo "INFO: Attempting to install Python via Homebrew..."

  # Check if Homebrew is available
  if ! command -v brew &> /dev/null; then
    echo "INFO: Homebrew not found. Installing Homebrew..."

    # Check if we can write to /usr/local or /opt/homebrew
    if [[ -w "/usr/local" ]] || [[ -w "/opt/homebrew" ]]; then
      echo "INFO: Installing Homebrew to system directory..."
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    else
      echo "INFO: No write permission to system directories. Installing Homebrew to user directory..."
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" --prefix=$HOME/.homebrew
      
      # Add user's Homebrew to PATH
      echo 'export PATH="$HOME/.homebrew/bin:$PATH"' >> ~/.bash_profile
      echo 'export PATH="$HOME/.homebrew/bin:$PATH"' >> ~/.zshrc
      export PATH="$HOME/.homebrew/bin:$PATH"
    fi

    # Homebrew installation path differs on Intel vs Apple Silicon Macs:
    if [ -d "/opt/homebrew/bin" ]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -d "/usr/local/bin" ]; then
      eval "$(/usr/local/bin/brew shellenv)"
    elif [ -d "$HOME/.homebrew/bin" ]; then
      export PATH="$HOME/.homebrew/bin:$PATH"
    fi

    # Verify brew is installed now
    if ! command -v brew &> /dev/null; then
      echo "WARN: Homebrew installation failed."
      return 1
    fi

    echo "INFO: Homebrew installation successful."
  fi

  # Try to install Python via Homebrew
  if brew install python; then
    return 0
  else
    echo "WARN: Homebrew Python installation failed."
    return 1
  fi
}

install_python_via_system() {
  echo "INFO: Attempting to install Python via system package manager..."

  # Check if Python is already available
  if command -v python3 &> /dev/null; then
    echo "INFO: Python3 already available via system."
    return 0
  fi

  # Try to install via system package manager
  if command -v port &> /dev/null; then
    echo "INFO: Installing Python via MacPorts..."
    sudo port install python3
    return $?
  fi

  echo "WARN: No system package manager found for Python installation."
  return 1
}

install_python_via_pyenv() {
  echo "INFO: Attempting to install Python via pyenv..."

  # Check if pyenv is available
  if ! command -v pyenv &> /dev/null; then
    echo "INFO: Installing pyenv..."
    
    # Install pyenv via Homebrew if available
    if command -v brew &> /dev/null; then
      brew install pyenv
    else
      echo "WARN: Homebrew not available for pyenv installation."
      return 1
    fi
  fi

  # Install Python via pyenv
  if pyenv install 3.11.0; then
    pyenv global 3.11.0
    return 0
  else
    echo "WARN: pyenv Python installation failed."
    return 1
  fi
}

install_python_via_download() {
  echo "INFO: Attempting to install Python via direct download..."

  # Determine system architecture
  ARCH=$(uname -m)
  PYTHON_VERSION="3.11.0"
  
  if [[ "$ARCH" == "arm64" ]]; then
    # Apple Silicon
    DOWNLOAD_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-macos11.pkg"
  else
    # Intel
    DOWNLOAD_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-macos10.9.pkg"
  fi

  echo "INFO: Downloading Python ${PYTHON_VERSION} for ${ARCH}..."
  
  # Download and install Python
  if curl -L -o /tmp/python.pkg "$DOWNLOAD_URL" && sudo installer -pkg /tmp/python.pkg -target /; then
    rm /tmp/python.pkg
    return 0
  else
    echo "WARN: Direct Python download failed."
    return 1
  fi
}

install_python_via_conda() {
  echo "INFO: Attempting to install Python via conda..."

  # Check if conda is available
  if ! command -v conda &> /dev/null; then
    echo "INFO: Installing Miniconda..."
    
    # Download and install Miniconda
    MINICONDA_URL="https://repo.anaconda.com/miniconda/Miniconda3-latest-MacOSX-$(uname -m).sh"
    
    if curl -L -o /tmp/miniconda.sh "$MINICONDA_URL" && bash /tmp/miniconda.sh -b -p $HOME/miniconda3; then
      rm /tmp/miniconda.sh
      export PATH="$HOME/miniconda3/bin:$PATH"
      echo 'export PATH="$HOME/miniconda3/bin:$PATH"' >> ~/.bash_profile
      echo 'export PATH="$HOME/miniconda3/bin:$PATH"' >> ~/.zshrc
    else
      echo "WARN: Miniconda installation failed."
      return 1
    fi
  fi

  # Install Python via conda
  if conda install python=3.11 -y; then
    return 0
  else
    echo "WARN: conda Python installation failed."
    return 1
  fi
}

install_python_windows() {
  echo "INFO: Installing Python on Windows..."

  # Method 1: Try winget (Windows Package Manager)
  if install_python_via_winget; then
    echo "INFO: Python installed successfully via winget."
    return 0
  fi

  # Method 2: Try chocolatey
  if install_python_via_chocolatey; then
    echo "INFO: Python installed successfully via chocolatey."
    return 0
  fi

  # Method 3: Try scoop
  if install_python_via_scoop; then
    echo "INFO: Python installed successfully via scoop."
    return 0
  fi

  # Method 4: Try direct download
  if install_python_via_download_windows; then
    echo "INFO: Python installed successfully via direct download."
    return 0
  fi

  # Method 5: Try Microsoft Store
  if install_python_via_store; then
    echo "INFO: Python installed successfully via Microsoft Store."
    return 0
  fi

  echo "ERROR: All Windows Python installation methods failed."
  return 1
}

install_python_via_winget() {
  echo "INFO: Attempting to install Python via winget..."

  # Check if winget is available
  if ! command -v winget &> /dev/null; then
    echo "WARN: winget not found. Skipping winget installation method."
    return 1
  fi

  # Try to install Python via winget
  if winget install Python.Python.3.11; then
    # Refresh PATH
    export PATH="$PATH:/c/Users/$USER/AppData/Local/Microsoft/WinGet/Packages/Python.Python.3.11_*"
    return 0
  else
    echo "WARN: winget Python installation failed."
    return 1
  fi
}

install_python_via_chocolatey() {
  echo "INFO: Attempting to install Python via chocolatey..."

  # Check if chocolatey is available
  if ! command -v choco &> /dev/null; then
    echo "INFO: Installing chocolatey..."
    
    # Install chocolatey
    if powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"; then
      # Refresh PATH
      export PATH="$PATH:/c/ProgramData/chocolatey/bin"
    else
      echo "WARN: chocolatey installation failed."
      return 1
    fi
  fi

  # Try to install Python via chocolatey
  if choco install python311 -y; then
    return 0
  else
    echo "WARN: chocolatey Python installation failed."
    return 1
  fi
}

install_python_via_scoop() {
  echo "INFO: Attempting to install Python via scoop..."

  # Check if scoop is available
  if ! command -v scoop &> /dev/null; then
    echo "INFO: Installing scoop..."
    
    # Install scoop
    if powershell -Command "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser; irm get.scoop.sh | iex"; then
      # Refresh PATH
      export PATH="$PATH:$HOME/scoop/apps/scoop/current/bin"
    else
      echo "WARN: scoop installation failed."
      return 1
    fi
  fi

  # Try to install Python via scoop
  if scoop install python311; then
    return 0
  else
    echo "WARN: scoop Python installation failed."
    return 1
  fi
}

install_python_via_download_windows() {
  echo "INFO: Attempting to install Python via direct download on Windows..."

  # Determine system architecture
  if [[ "$(uname -m)" == "x86_64" ]]; then
    ARCH="amd64"
  else
    ARCH="win32"
  fi

  PYTHON_VERSION="3.11.0"
  DOWNLOAD_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-${ARCH}.exe"

  echo "INFO: Downloading Python ${PYTHON_VERSION} for Windows ${ARCH}..."
  
  # Download Python installer
  if curl -L -o /tmp/python-installer.exe "$DOWNLOAD_URL"; then
    # Install Python silently
    if /tmp/python-installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0; then
      rm /tmp/python-installer.exe
      # Refresh PATH
      export PATH="$PATH:/c/Python311:/c/Python311/Scripts"
      return 0
    else
      echo "WARN: Python installer execution failed."
      rm /tmp/python-installer.exe
      return 1
    fi
  else
    echo "WARN: Python download failed."
    return 1
  fi
}

install_python_via_store() {
  echo "INFO: Attempting to install Python via Microsoft Store..."

  # Try to install Python via Microsoft Store
  if powershell -Command "Get-AppxPackage -Name 'PythonSoftwareFoundation.Python.3.11' -ErrorAction SilentlyContinue | Install-AppxPackage"; then
    return 0
  else
    echo "WARN: Microsoft Store Python installation failed."
    return 1
  fi
}

install_keeper_secrets_manager_core() {
  echo "INFO: Attempting to install keeper-secrets-manager-core via pip3..."

  # Check if pip3 is installed
  if ! command -v pip3 &> /dev/null; then
      # If pip3 is not found, attempting to install pip3
      if ! install_pip3; then
          echo "ERROR: Failed to install pip3. Please install Python manually."
          echo "INFO: You can install Python from: https://www.python.org/downloads/"
          return 1
      fi
  fi

  # Try to install keeper-secrets-manager-core
  if ! pip3 install -U keeper-secrets-manager-core; then
    echo "ERROR: 'keeper-secrets-manager-core install' failed."
    echo "INFO: Please check your internet connection and try again."
    return 1
  fi

  echo "INFO: keeper-secrets-manager-core installation successful."
  return 0
}

# --- Main Execution Logic ---
install_keeper_secrets_manager_core