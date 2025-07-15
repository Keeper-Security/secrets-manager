#!/usr/bin/env python3

import os
import sys
import json
import argparse
import platform
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import FileKeyValueStorage, InMemoryKeyValueStorage
from keeper_secrets_manager_core.exceptions import KeeperError

# -------------------- Constants --------------------

class Constants:
    DEFAULT_PATH = "C:\\ProgramData\\keeper_secret_manager" if platform.system() == 'Windows' else "/opt/keeper_secret_manager"
    INPUT_FILE = "input.json"
    CONFIG_FILE = "keeper_config.json"
    OUTPUT_FILE = "keeper_output.txt"
    ENV_FILE = "keeper_env.sh"
    AUTHENTICATION = "authentication"
    SECRETS = "secrets"
    FOLDERS = "folders"
    AUTH_VALUE_ENV_VAR = "KEEPER_CONFIG"
    KEEPER_NOTATION_PREFIX = "keeper://"
    
# -------------------- Get Environment Variables  --------------------

def get_env_from_current_process(env_var_name):
    """
    Get environment variable from current process environment.
    
    Args:
        env_var_name (str): Name of the environment variable to retrieve
        
    Returns:
        str or None: Environment variable value if found, None otherwise
    """
    return os.getenv(env_var_name)

def get_env_value(env_var_name):
    """
    Get environment variable value from multiple possible sources.
    Checks standard environment, shell profiles, and system-specific locations.
    
    Args:
        env_var_name (str): Name of the environment variable to retrieve
        
    Returns:
        str or None: Environment variable value if found, None otherwise
    """
    # Check current process environment (fastest)
    value = get_env_from_current_process(env_var_name)
    if value:
        return value
    
    return None

# -------------------- Logging & Custom Exceptions --------------------

def log_message(level, message):
    print(f"[{level}] KEEPER: {message}", file=sys.stderr)

class KSMInitializationError(Exception): pass
class ConfigurationError(Exception): pass

# -------------------- Config & Auth Logic --------------------

def get_configurations(config_file_path):
    try:
        if not os.path.exists(config_file_path):
            raise ConfigurationError(f"Configuration file does not exist: {config_file_path}")
        if not os.access(config_file_path, os.R_OK):
            raise ConfigurationError(f"Cannot read configuration file: {config_file_path}")
        with open(config_file_path, 'r', encoding='utf-8') as file:
            config = json.load(file)
        if not isinstance(config, dict):
            raise ConfigurationError("Configuration file must contain a JSON object")
        return config
    except json.JSONDecodeError as e:
        raise ConfigurationError(f"Invalid JSON in configuration file: {e}") from e
    except Exception as e:
        if isinstance(e, ConfigurationError):
            raise
        raise ConfigurationError(f"Failed to read configuration file: {e}") from e
    
def validate_auth_config(auth_config):
    
    if not isinstance(auth_config, (list)) or len(auth_config) < 1:
        raise ValueError("Authentication config not provided as required")
    
    if auth_config[0] not in ['token', 'json', 'base64']:
        raise ValueError("Unsupported authentication method, Must be one of: token, json, base64")
    
    method = auth_config[0]
    
    # Check environment variable first
    env_value = get_env_value(Constants.AUTH_VALUE_ENV_VAR)
    if env_value:
        value = env_value
    elif len(auth_config) > 1 and auth_config[1] != "" and auth_config[1] is not None:
        value = auth_config[1]
    else:
        raise ValueError("Authentication value not found in configuration or KEEPER_CONFIG not exposed to environment")
    
    return method, value

def is_config_expired(secrets_manager):
    try:
        secrets_manager.get_secrets()
        return False
    except KeeperError as e:
        msg = str(e).lower()
        patterns = ['access_denied', 'signature is invalid', 'authentication failed', 'token expired']
        if any(p in msg for p in patterns):
            log_message("INFO", "Credentials appear to be expired")
            return True
        raise

def initialize_ksm(auth_config):
    method, value = validate_auth_config(auth_config)
    config_file_path = os.path.join(Constants.DEFAULT_PATH, Constants.CONFIG_FILE)
    
    # Check if keeper_config.json file exists and is not empty
    if method in ['token', 'json'] and os.path.exists(config_file_path) and os.path.getsize(config_file_path) > 0:
        try:
            sm = SecretsManager(config=FileKeyValueStorage(config_file_path))
            
            # Check if current keeper_config.json is not expired
            if not is_config_expired(sm):
                return sm
            
            # Remove the expired keeper_config.json file
            os.remove(config_file_path)
        except Exception as e:
            try: 
                os.remove(config_file_path)
            except: 
                pass
    
    if method == 'token':
        return _authenticate_with_token(value, config_file_path)
    elif method == 'base64':
        return _authenticate_with_base64(value)
    elif method == 'json':
        return _authenticate_with_json(config_file_path)
    else:
        raise ValueError(f"Unsupported method: {method}")

def _authenticate_with_token(token, config_file_path):
    sm = SecretsManager(token=token, config=FileKeyValueStorage(config_file_path))
    sm.get_secrets()
    return sm

def _authenticate_with_base64(base64_string):
    sm = SecretsManager(config=InMemoryKeyValueStorage(base64_string))
    sm.get_secrets()
    return sm

def _authenticate_with_json(config_file_path):
    if not os.path.exists(config_file_path):
        raise ValueError("Keeper JSON configuration file not found.")
    sm = SecretsManager(config=FileKeyValueStorage(config_file_path))
    sm.get_secrets()
    return sm

# --------------------  Secret Processing using Keeper Notation --------------------

def parse_secret_notation(secret_string):
    """
    Parse secret string.
    
    Examples:
    - "EG6KdJaaLG7esRZbMnfbFA/custom_field/Label1 > APP_PASSWORD" -> (keeper_notation, APP_PASSWORD, None)
    - "EG6KdJaaLG7esRZbMnfbFA/custom_field/API_KEY" -> (keeper_notation, API_KEY, None)
    - "EG6KdJaaLG7esRZbMnfbFA/custom_field/Token > env:TOKEN" -> (keeper_notation, TOKEN, env)
    - "bf3dg-99-JuhoaeswgtFxg/file/credentials.txt > file:/tmp/Certificate.crt" -> (keeper_notation, /tmp/Certificate.crt, file)
    
    Returns:
        tuple: (keeper_notation, output_name, action_type)
    """
    if ">" not in secret_string:
        # No output specification, extract field name from keeper notation as key
        keeper_notation = secret_string.strip()
        # Extract the last part of the notation as the default key
        parts = keeper_notation.split('/')
        if len(parts) < 2:
            raise ValueError(f"Invalid keeper notation: {secret_string}")
        
        # For file notation, use filename without extension as key
        if '/file/' in keeper_notation:
            filename = parts[-1]
            field_name = os.path.splitext(filename)[0]  # Remove extension
        else:
            field_name = parts[-1]  # Last part is the field name
        
        return keeper_notation, field_name, None
    else:
        # Has output specification
        parts = secret_string.split('>')
        if len(parts) != 2:
            raise ValueError(f"Invalid secret structure: {secret_string}. Expected format: keeper_notation > output_spec")
        
        keeper_notation = parts[0].strip()
        right_part = parts[1].strip()
        
        # Parse the right part for action type
        if right_part.startswith('env:'):
            output_name = right_part[4:]  # Remove 'env:' prefix
            action_type = 'env'
        elif right_part.startswith('file:'):
            output_name = right_part[5:]  # Remove 'file:' prefix
            action_type = 'file'
        else:
            output_name = right_part
            action_type = None
        
        return keeper_notation, output_name, action_type

def process_secret_notation(sm, keeper_notation, output_name, action_type, cumulative_output):
    """
    Process a single secret using Keeper notation and get_notation method.
    
    Args:
        sm: SecretsManager instance
        keeper_notation: Keeper notation string without prefix (e.g., "EG6KdJaaLG7esRZbMnfbFA/custom_field/Label1")
        output_name: Name to use in output
        action_type: Type of action (env, file, or None for direct output)
        cumulative_output: Dictionary to accumulate output
    """
    try:
        # Add the keeper:// prefix to the notation
        full_notation = Constants.KEEPER_NOTATION_PREFIX + keeper_notation
        
        value = sm.get_notation(full_notation)
        
        # Handle different action types
        if action_type == 'env':
            # Export as environment variable
            env_path = os.path.join(Constants.DEFAULT_PATH, Constants.ENV_FILE)
            os.makedirs(Constants.DEFAULT_PATH, exist_ok=True)
            with open(env_path, "a") as env_file:
                env_file.write(f'export {output_name}="{value}"\n')
            
            # Don't add to JSON output for env variables
        elif action_type == 'file':
            # For file action, get_notation returns file content, so we need to write it to the specified path
            os.makedirs(os.path.dirname(output_name), exist_ok=True)
            
            # Handle binary content for files
            if isinstance(value, bytes):
                with open(output_name, 'wb') as f:
                    f.write(value)
            else:
                with open(output_name, 'w') as f:
                    f.write(str(value))
                    
            filename = os.path.basename(output_name)
            key_name = os.path.splitext(filename)[0]
            
            # Add the file path to output
            cumulative_output[key_name] = output_name
        else:
            # Add to JSON output for direct values
            if output_name.strip() == "":
                output_name = keeper_notation.split('/')[-1]
                
            cumulative_output[output_name] = value
                
    except Exception as e:
        log_message("ERROR", f"Failed to process keeper notation '{keeper_notation}': {e}")
        raise

def process_secrets_array(sm, secrets_array, cumulative_output):
    """
    Process an array of secret strings using Keeper notation.
    
    Args:
        sm: SecretsManager instance
        secrets_array: Array of secret strings
        cumulative_output: Dictionary to accumulate output
    """
    for secret_string in secrets_array:
        try:
            keeper_notation, output_name, action_type = parse_secret_notation(secret_string)
            process_secret_notation(sm, keeper_notation, output_name, action_type, cumulative_output)
        except Exception as e:
            log_message("ERROR", f"Failed to process secret '{secret_string}': {e}")
            continue

# -------------------- Core Functions --------------------

def process_folders(sm, folders_config, cumulative_output):
    for key, value in folders_config.items(): 
        # Fetch all folders
        if(key == "list_all"):
            try:
                folders = sm.get_folders()
                    
                folder_output = []
                for folder in folders:
                    folder_output.append({
                        "folder_uid": folder.folder_uid,
                        "name": folder.name,
                        "parent_uid": folder.parent_uid,
                    })
                cumulative_output["folders"] = folder_output
            except Exception as e:
                log_message("ERROR", f"Failed to get all folders: {e}")
                continue
    

# -------------------- Main --------------------

def main():    
    parser = argparse.ArgumentParser(description="Keeper Secrets CLI")
    parser.add_argument("--input", help="Path to input.json")
    args = parser.parse_args()

    input_path = args.input if args.input else os.path.join(Constants.DEFAULT_PATH, Constants.INPUT_FILE)

    try:
        config = get_configurations(input_path)
    except Exception as e:
        log_message("ERROR", str(e))
        sys.exit(1)

    auth_config = config.get(Constants.AUTHENTICATION)
    secrets_config = config.get(Constants.SECRETS, [])
    folders_config = config.get(Constants.FOLDERS, {})

    cumulative_output = {}

    try:
        sm = initialize_ksm(auth_config)

        # Process secrets array (GitHub Actions-like format)
        if isinstance(secrets_config, list):
            process_secrets_array(sm, secrets_config, cumulative_output)
        else:
            log_message("ERROR", "Secrets must be provided as an array of strings")
            sys.exit(1)

        # Perform folder operations
        process_folders(sm, folders_config, cumulative_output)
        
        # Always output as JSON
        if cumulative_output:
            print(json.dumps(cumulative_output, indent=2))

    except Exception as e:
        log_message("ERROR", f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()