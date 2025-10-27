# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2023 Keeper Security Inc.
# Contact: sm@keepersecurity.com
"""KSM interpolate command - Replace Keeper notation in template files with secret values

Simple, secure, and powerful template interpolation for DevOps workflows.
"""

import base64
import hashlib
import json
import os
import re
import sys
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from colorama import Fore, Style
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_cli.exception import KsmCliException


class Interpolate:
    """Action for interpolating Keeper notation in template files

    Simple for basic use, powerful for advanced workflows, secure by default.

    BASIC USAGE:
        ksm interpolate config.env                    # Output to stdout
        ksm interpolate config.env -o output.env      # Output to file
        ksm interpolate -w config.env                 # In-place editing
        ksm interpolate -n config.env                 # Dry-run (no changes)

    SECURITY FEATURES (automatic):
        - File permissions (0600 for output files)
        - Path traversal prevention
        - Git safety warnings
        - Template injection protection
        - Safety marker files (.filename.ksm-secret)

    ADVANCED FEATURES:
        1. Default values (fallback if secret not found - shell-style :-):
           PASSWORD=keeper://DB/field/password:-default_password
           DB_HOST=keeper://DB/field/host:-localhost

        2. Transformations (no new dependencies!):
           # Base64 encoding
           ENCODED=keeper://API/field/key|base64

           # URL encoding
           URL_PARAM=keeper://Config/field/value|urlencode

           # Uppercase/lowercase
           UPPER_KEY=keeper://API/field/key|upper

           # Hashing
           PASSWORD_HASH=keeper://Auth/field/password|sha256

           Available: base64, base64url, urlencode, urlencodeplus,
                      upper, lower, trim, sha256, md5

        3. Comment preservation (lines starting with #):
           # This comment with keeper://notation is NOT processed
           PASSWORD=keeper://DB/field/password  # This IS processed

        4. Better error messages:
           - Shows line numbers
           - Suggests fixes
           - Lists available fields
           - Checks permissions

    EXAMPLES:
        # Local development with defaults (use :- like shell variables)
        DB_HOST=keeper://DB/field/host:-localhost
        DB_PORT=keeper://DB/field/port:-5432

        # CI/CD with transformations
        JWT_SECRET=keeper://Auth/field/secret|base64
        API_KEY=keeper://API/field/key|urlencode

        # Multiple files
        ksm interpolate *.template

        # Validation before production
        ksm interpolate -n -v production.env.template
    """

    # Security constants
    SECURE_FILE_PERMS = 0o600
    SECURE_DIR_PERMS = 0o700
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

    DANGEROUS_PATH_PATTERNS = [
        re.compile(r'\.\.'),      # Parent directory traversal (..)
        re.compile(r'^~'),        # Home directory reference (~)
    ]

    DANGEROUS_TEMPLATE_PATTERNS = [
        # Use bounded repetition to prevent ReDoS attacks
        (re.compile(r'\{\{.{0,200}?exec.{0,200}?\}\}', re.IGNORECASE), "Potential code execution"),
        (re.compile(r'\{\{.{0,200}?eval.{0,200}?\}\}', re.IGNORECASE), "Potential code evaluation"),
        (re.compile(r'\{\{.{0,200}?__.{0,200}?\}\}', re.IGNORECASE), "Access to private attributes"),
        (re.compile(r'<%.{0,200}?exec.{0,200}?%>', re.IGNORECASE), "Potential code execution"),
    ]

    # Improved notation pattern - more permissive for field names with spaces
    # Supports: keeper://UID/TYPE/FIELD[:-default][|transform]
    # Based on PR #854's pattern + extended for defaults and transforms
    # Using :- for defaults (shell-style) to avoid ambiguity with colons in connection strings
    KEEPER_NOTATION_PATTERN = re.compile(
        r'keeper://([^\s/]+)/([^\s/]+)/([^"\'\n#:|@\s]+)'  # Base: keeper://UID/TYPE/FIELD (stop at @)
        r'(?::-([^|"\'\n#@\s]+))?'                          # Optional :-default_value
        r'(?:\|([^\s"\'\n#@]+))?'                           # Optional |transform
    )

    # Simple transformations (no new dependencies!)
    TRANSFORMS = {
        'base64': lambda v: base64.b64encode(v.encode()).decode(),
        'base64url': lambda v: base64.urlsafe_b64encode(v.encode()).decode().rstrip('='),
        'urlencode': lambda v: urllib.parse.quote(v),
        'urlencodeplus': lambda v: urllib.parse.quote_plus(v),
        'upper': lambda v: v.upper(),
        'lower': lambda v: v.lower(),
        'trim': lambda v: v.strip(),
        'sha256': lambda v: hashlib.sha256(v.encode()).hexdigest(),
        'md5': lambda v: hashlib.md5(v.encode()).hexdigest(),
    }

    def __init__(self, cli):
        self.cli = cli
        self.accessed_records = set()
        self.replacements_count = 0
        self.errors = []
        self.warnings = []
        self.used_defaults = []  # Track when defaults are used
        self.secret_cache = {}  # Cache to avoid duplicate API calls

    # ========================================================================
    # SECURITY METHODS (merged from InterpolateSecurity)
    # ========================================================================

    def _validate_path(self, file_path: str, base_dir: str = None) -> str:
        """Validate and sanitize file paths to prevent traversal attacks"""
        # Remove null bytes
        file_path = file_path.replace('\0', '')

        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATH_PATTERNS:
            if pattern.search(file_path):
                raise KsmCliException(f"Unsafe path pattern detected: {file_path}")

        # Resolve to absolute path
        path = Path(file_path)
        if not path.is_absolute():
            base = Path(base_dir or os.getcwd())
            path = base / path

        # Security: Reject symlinks to prevent symlink attacks
        if path.is_symlink():
            raise KsmCliException(f"Symlinks not allowed: {file_path}")

        resolved = path.resolve()

        # Ensure path is within allowed directory
        if base_dir:
            base = Path(base_dir).resolve()
            try:
                resolved.relative_to(base)
            except ValueError:
                raise KsmCliException(f"Path '{file_path}' is outside allowed directory")

        return str(resolved)

    def _check_git_safety(self, file_path: str) -> Dict[str, any]:
        """Check if file is safe from git commits"""
        path = Path(file_path)
        warnings = []

        # Find git root
        git_root = self._find_git_root(path)
        if not git_root:
            return {"safe": True, "warnings": []}

        # Check .gitignore
        if not self._is_gitignored(path, git_root):
            warnings.append(f"File is not in .gitignore. Add '{path.relative_to(git_root)}' to .gitignore")

        # Check if filename suggests secrets
        secret_patterns = ['secret', 'password', 'key', 'token', 'credential', '.env']
        if any(pattern in path.name.lower() for pattern in secret_patterns):
            warnings.append("Filename suggests it may contain secrets")

        return {"safe": len(warnings) == 0, "warnings": warnings}

    def _find_git_root(self, path: Path) -> Optional[Path]:
        """Find the git repository root"""
        current = path.parent if path.is_file() else path
        while current != current.parent:
            if (current / ".git").is_dir():
                return current
            current = current.parent
        return None
    
    def _is_gitignored(self, file_path: Path, git_root: Path) -> bool:
        """Simple check if file matches gitignore patterns"""
        gitignore = git_root / ".gitignore"
        if not gitignore.exists():
            return False
        
        relative_path = str(file_path.relative_to(git_root))
        
        try:
            with open(gitignore, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Simple pattern matching
                        if line.endswith('/'):
                            # Directory pattern
                            if relative_path.startswith(line):
                                return True
                        elif '*' in line:
                            # Glob pattern (simple implementation)
                            pattern = line.replace('*', '.*')
                            if re.match(pattern, relative_path):
                                return True
                        else:
                            # Exact match or prefix
                            if relative_path == line or relative_path.startswith(line + '/'):
                                return True
        except Exception:
            pass
        
        return False
    
    def _validate_template(self, content: str) -> None:
        """Validate template content for security issues"""
        for pattern, message in self.DANGEROUS_TEMPLATE_PATTERNS:
            if pattern.search(content):
                raise KsmCliException(f"Security violation in template: {message}")

    def _create_safety_marker(self, file_path: str) -> None:
        """Create a marker file to warn about sensitive content"""
        path = Path(file_path)
        marker_path = path.parent / f".{path.name}.ksm-secret"
        
        marker_content = {
            "warning": "This file contains interpolated secrets from Keeper",
            "file": path.name,
            "created": datetime.utcnow().isoformat(),
            "do_not_commit": True
        }
        
        try:
            with open(marker_path, 'w') as f:
                json.dump(marker_content, f, indent=2)
            marker_path.chmod(0o600)
        except Exception:
            # Don't fail if marker can't be created
            pass

    # ========================================================================
    # CORE INTERPOLATION METHODS
    # ========================================================================

    def interpolate(self, **kwargs):
        """Main action for interpolating template files"""
        # Get input and output options
        input_files = kwargs.get('input_file', [])
        output_file = kwargs.get('output_file')
        in_place = kwargs.get('in_place', False)
        backup_suffix = kwargs.get('backup_suffix', '.bak')
        dry_run = kwargs.get('dry_run', False)
        verbose = kwargs.get('verbose', False)
        continue_on_error = kwargs.get('continue', False)
        validate = kwargs.get('validate', False)
        allow_unsafe_for_eval = kwargs.get('allow_unsafe_for_eval', False)

        # Pass options to processing methods
        self.allow_unsafe_for_eval = allow_unsafe_for_eval

        # Process stdin if no input files
        if not input_files:
            content = sys.stdin.read()
            result = self._process_content(content, dry_run, verbose)
            
            if not dry_run:
                if output_file:
                    self._write_output(result, output_file)
                else:
                    sys.stdout.write(result)
            
            self._report_results(dry_run, verbose)
            return

        # Process input files
        for input_file in input_files:
            try:
                self._process_file(
                    input_file, output_file, in_place, backup_suffix,
                    dry_run, verbose, continue_on_error
                )
            except Exception as e:
                if not continue_on_error:
                    raise
                self.errors.append(f"Error processing {input_file}: {str(e)}")

        # Validate all notations were resolved
        if validate and self.errors:
            raise KsmCliException("Validation failed: not all notations could be resolved")

        self._report_results(dry_run, verbose)

    def _process_file(self, input_file, output_file, in_place, backup_suffix,
                      dry_run, verbose, continue_on_error):
        """Process a single file"""
        # Validate input file path
        try:
            input_file = self._validate_path(input_file)
        except Exception as e:
            error_msg = f"Invalid input path: {str(e)}"
            if continue_on_error:
                self.errors.append(error_msg)
                return
            else:
                raise

        # Read input file with size limit (prevents TOCTOU race condition)
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                # Read with limit to prevent reading huge files
                content = f.read(self.MAX_FILE_SIZE + 1)

                # Check size after reading (no TOCTOU race)
                if len(content) > self.MAX_FILE_SIZE:
                    error_msg = f"File {input_file} exceeds maximum size of {self.MAX_FILE_SIZE // 1024 // 1024}MB"
                    if continue_on_error:
                        self.errors.append(error_msg)
                        return
                    else:
                        raise KsmCliException(error_msg)

        except UnicodeDecodeError:
            error_msg = f"{input_file} must be UTF-8 text (binary files not supported)"
            if continue_on_error:
                self.errors.append(error_msg)
                return
            else:
                raise KsmCliException(error_msg)
        except (FileNotFoundError, PermissionError) as e:
            error_msg = f"Cannot read {input_file}: {str(e)}"
            if continue_on_error:
                self.errors.append(error_msg)
                return
            else:
                raise KsmCliException(error_msg)
        except Exception as e:
            error_msg = f"Failed to read {input_file}: {str(e)}"
            if continue_on_error:
                self.errors.append(error_msg)
                return
            else:
                raise KsmCliException(error_msg)
        
        # Validate template content
        try:
            self._validate_template(content)
        except Exception as e:
            error_msg = f"Template validation failed for {input_file}: {str(e)}"
            if continue_on_error:
                self.errors.append(error_msg)
                return
            else:
                raise

        # Process content
        result = self._process_content(content, dry_run, verbose)

        if dry_run:
            return

        # Handle output
        if in_place:
            # Create backup if requested
            if backup_suffix:
                backup_path = f"{input_file}{backup_suffix}"
                try:
                    with open(backup_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                except Exception as e:
                    raise KsmCliException(f"Failed to create backup {backup_path}: {str(e)}")

            # Write result back to input file securely
            try:
                # Use atomic write for in-place editing
                temp_path = Path(input_file).with_suffix('.tmp')
                with open(temp_path, 'w', encoding='utf-8') as f:
                    os.fchmod(f.fileno(), self.SECURE_FILE_PERMS)
                    f.write(result)
                    f.flush()
                    os.fsync(f.fileno())

                # Atomic rename
                os.rename(temp_path, input_file)

                # Create safety marker
                self._create_safety_marker(input_file)
            except Exception as e:
                if temp_path.exists():
                    temp_path.unlink()
                raise KsmCliException(f"Failed to write to {input_file}: {str(e)}")
        elif output_file:
            self._write_output(result, output_file)
        else:
            sys.stdout.write(result)

    def _process_content(self, content, dry_run, verbose):
        """Process content and replace Keeper notations

        Features:
        - Preserves comment lines (lines starting with #)
        - Supports defaults: keeper://UID/field/name:default_value
        - Supports transforms: keeper://UID/field/name|base64
        - Smart error messages with suggestions
        """
        lines = content.split('\n')
        processed_lines = []

        # Collect all notations for pre-loading
        all_base_notations = set()

        for line_num, line in enumerate(lines, 1):
            # Skip comment lines (like PR #854) - preserves comments
            if line.lstrip().startswith('#'):
                processed_lines.append(line)
                if dry_run and verbose:
                    print(f"  Line {line_num}: [COMMENT] skipped", file=sys.stderr)
                continue

            # Find all notations in this line
            matches = list(self.KEEPER_NOTATION_PATTERN.finditer(line))

            if not matches:
                processed_lines.append(line)
                continue

            # Collect base notations for pre-loading
            for match in matches:
                uid, field_type, field_name = match.group(1), match.group(2), match.group(3)
                base_notation = f"keeper://{uid}/{field_type}/{field_name}"
                all_base_notations.add(base_notation)

            processed_lines.append(line)

        # Pre-load records for better performance
        if not dry_run:
            self._preload_records(list(all_base_notations))

        # Now process each line
        result_lines = []
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.lstrip().startswith('#'):
                result_lines.append(line)
                continue

            matches = list(self.KEEPER_NOTATION_PATTERN.finditer(line))
            if not matches:
                result_lines.append(line)
                continue

            processed_line = line
            for match in matches:
                full_notation = match.group(0)
                uid, field_type, field_name = match.group(1), match.group(2), match.group(3)
                default_value = match.group(4)  # Optional :default
                transform = match.group(5)  # Optional |transform

                base_notation = f"keeper://{uid}/{field_type}/{field_name}"

                if dry_run:
                    # Dry run: check accessibility
                    try:
                        self._get_secret(base_notation)
                        status = "OK (accessible)"
                    except Exception as e:
                        error_str = str(e).lower()
                        if "not found" in error_str or "does not exist" in error_str:
                            status = "ERROR (not found)"
                        elif "access" in error_str or "permission" in error_str:
                            status = "ERROR (access denied)"
                        else:
                            status = f"ERROR: {str(e)[:40]}"
                    if verbose:
                        print(f"  Line {line_num}: {full_notation} - {status}", file=sys.stderr)
                    continue

                try:
                    # Get secret value (with caching)
                    value = self._get_secret(base_notation)

                    # Security: Check for shell injection risk (fails by default!)
                    self._check_shell_injection_risk(value, base_notation)

                    # Apply transformation if specified
                    if transform:
                        if transform not in self.TRANSFORMS:
                            available = ', '.join(sorted(self.TRANSFORMS.keys()))
                            raise KsmCliException(
                                f"Unknown transform '{transform}' in {full_notation}\n"
                                f"Available transforms: {available}"
                            )
                        try:
                            value = self.TRANSFORMS[transform](value)
                        except Exception as e:
                            raise KsmCliException(f"Transform '{transform}' failed for {full_notation}: {e}")

                    # Replace in line
                    processed_line = processed_line.replace(full_notation, value, 1)
                    self.replacements_count += 1

                    if verbose:
                        transform_desc = f"|{transform}" if transform else ""
                        print(f"  OK Line {line_num}: {base_notation}{transform_desc} - [REPLACED]", file=sys.stderr)

                except Exception as e:
                    # Re-raise transform errors (don't use defaults for transform failures)
                    if "Transform" in str(e) or "Unknown transform" in str(e):
                        raise

                    # Use default value if provided
                    if default_value:
                        # Security: Check default values for shell injection too!
                        self._check_shell_injection_risk(default_value, f"{base_notation}:default")

                        # Apply transformation to default value if specified
                        final_value = default_value
                        if transform:
                            if transform not in self.TRANSFORMS:
                                available = ', '.join(sorted(self.TRANSFORMS.keys()))
                                raise KsmCliException(
                                    f"Unknown transform '{transform}' in {full_notation}\n"
                                    f"Available transforms: {available}"
                                )
                            try:
                                final_value = self.TRANSFORMS[transform](default_value)
                            except Exception as transform_err:
                                raise KsmCliException(f"Transform '{transform}' failed for default value: {transform_err}")

                        processed_line = processed_line.replace(full_notation, final_value, 1)
                        self.used_defaults.append((base_notation, default_value))
                        if verbose:
                            print(f"  WARNING Line {line_num}: {base_notation} - using default: {default_value}", file=sys.stderr)
                    else:
                        # Better error message with suggestions (inlined for simplicity)
                        error_str = str(e).lower()
                        if "not found" in error_str:
                            if "record" in error_str:
                                error_msg = f"Line {line_num}: Record '{uid}' not found (check UID and sharing)"
                            else:
                                error_msg = f"Line {line_num}: Field '{field_name}' not found in '{uid}' (check field name)"
                        elif "access" in error_str or "permission" in error_str:
                            error_msg = f"Line {line_num}: Access denied to {base_notation} (check sharing)"
                        elif "invalid" in error_str:
                            error_msg = f"Line {line_num}: Invalid notation format: {base_notation}"
                        else:
                            error_msg = f"Line {line_num}: {base_notation} - {str(e)}"

                        self.errors.append(error_msg)
                        if verbose:
                            print(f"  ERROR Line {line_num}: {error_msg}", file=sys.stderr)

            result_lines.append(processed_line)

        return '\n'.join(result_lines)

    def _preload_records(self, notations):
        """Pre-load records for better performance"""
        # Extract unique record UIDs
        uids = set()
        for notation in notations:
            # Parse the notation to get UID
            parts = notation.replace('keeper://', '').split('/')
            if parts and parts[0]:
                uids.add(parts[0])

        # Load all records in one call
        if uids:
            try:
                # Get secrets manager instance
                records = self.cli.client.get_secrets(list(uids))
                # Records are automatically cached by the SDK
                for uid in uids:
                    self.accessed_records.add(uid)
            except Exception as e:
                self.warnings.append(f"Failed to preload records: {str(e)}")

    def _get_secret(self, notation):
        """Get secret value with caching to avoid duplicate API calls"""
        if notation not in self.secret_cache:
            # Use client method directly (like exec.py does)
            value = self.cli.client.get_notation(notation)

            # Convert dict/list to JSON string
            if isinstance(value, (dict, list)):
                value = json.dumps(value)

            self.secret_cache[notation] = str(value)

            # Track accessed record
            parts = notation.replace('keeper://', '').split('/')
            if parts and parts[0]:
                self.accessed_records.add(parts[0])

        return self.secret_cache[notation]

    def _check_shell_injection_risk(self, value: str, notation: str) -> None:
        """Check if secret value contains shell metacharacters that could enable command injection

        Security Issue: If users run 'eval "$(ksm interpolate ...)"' and a malicious user
        has write access to Keeper records, they can inject arbitrary commands via:
        - Newlines (execute multiple commands)
        - Command substitution $(...) or backticks
        - Semicolons, pipes, redirects
        - Variable expansion

        By default, we FAIL if unsafe characters are detected.
        Users must explicitly acknowledge the risk with --allow-unsafe-for-eval flag.
        """
        # Shell metacharacters that enable command injection
        dangerous_patterns = {
            '\n': 'newline (allows command chaining)',
            '\r': 'carriage return',
            '`': 'backtick (command substitution)',
            '$': 'dollar sign (variable/command expansion)',
            ';': 'semicolon (command separator)',
            '|': 'pipe (command chaining)',
            '&': 'ampersand (background execution)',
            '>': 'redirect (file overwrite)',
            '<': 'redirect (file read)',
        }

        found_dangerous = []
        for char, description in dangerous_patterns.items():
            if char in value:
                found_dangerous.append(f"'{char}' ({description})")

        if found_dangerous:
            if not self.allow_unsafe_for_eval:
                # FAIL by default - secure!
                error_msg = (
                    f"\nSECURITY ERROR: Secret {notation} contains shell metacharacters:\n"
                    f"  {', '.join(found_dangerous)}\n\n"
                    f"This is DANGEROUS if you plan to use 'eval' or 'source' with the output!\n\n"
                    f"A malicious user with Keeper write access could inject arbitrary commands.\n"
                    f"Example attack: Setting a password to: password\\nrm -rf /\\n\n\n"
                    f"OPTIONS:\n"
                    f"  1. [RECOMMENDED] Write to file instead of using eval:\n"
                    f"     ksm interpolate secrets.env -o /tmp/secrets.env\n"
                    f"     source /tmp/secrets.env && rm /tmp/secrets.env\n\n"
                    f"  2. [RISKY] Acknowledge the risk (only if you fully trust Keeper write access):\n"
                    f"     ksm interpolate secrets.env --allow-unsafe-for-eval\n\n"
                    f"  3. [SAFE] Use 'ksm exec' instead for environment variables\n"
                )
                raise KsmCliException(error_msg)
            else:
                # User explicitly allowed - warn them!
                color = Fore.RED if self.cli.use_color else ''
                reset = Style.RESET_ALL if self.cli.use_color else ''
                warning = (
                    f"\n{color}SECURITY WARNING: Secret {notation} contains shell metacharacters{reset}\n"
                    f"  Characters found: {', '.join(found_dangerous)}\n"
                    f"  This could enable command injection if used with eval/source!\n"
                    f"  Proceeding because --allow-unsafe-for-eval flag was used.\n"
                )
                print(warning, file=sys.stderr)
                self.warnings.append(f"Secret {notation} contains dangerous shell characters")

    # ========================================================================
    # FILE OPERATIONS
    # ========================================================================

    def _write_output(self, content, output_file):
        """Write content to output file with secure permissions"""
        try:
            # Validate output path
            output_file = self._validate_path(output_file)
            output_path = Path(output_file)

            # Check git safety
            git_check = self._check_git_safety(output_file)
            if not git_check["safe"] and self.cli.use_color:
                print(f"\n{Fore.YELLOW}Git safety warnings:{Style.RESET_ALL}", file=sys.stderr)
                for warning in git_check["warnings"]:
                    print(f"  - {warning}", file=sys.stderr)
            elif not git_check["safe"]:
                print(f"\nGit safety warnings:", file=sys.stderr)
                for warning in git_check["warnings"]:
                    print(f"  - {warning}", file=sys.stderr)
            
            # Ensure parent directory exists with secure permissions
            output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            
            # Write file atomically with secure permissions
            temp_path = output_path.with_suffix('.tmp')
            try:
                with open(temp_path, 'w', encoding='utf-8') as f:
                    # Set permissions before writing
                    os.fchmod(f.fileno(), self.SECURE_FILE_PERMS)
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())

                # Atomic rename
                os.rename(temp_path, output_path)

                # Create safety marker
                self._create_safety_marker(output_file)
                
            except Exception:
                if temp_path.exists():
                    temp_path.unlink()
                raise
                
        except Exception as e:
            raise KsmCliException(f"Failed to write output file {output_file}: {str(e)}")

    def _report_results(self, dry_run, verbose):
        """Report interpolation results with clear, actionable information"""
        if dry_run:
            print(f"\nDry-run complete:", file=sys.stderr)
            print(f"  - Found {len(self.accessed_records)} unique record(s)", file=sys.stderr)
            if self.errors:
                print(f"  - {len(self.errors)} error(s) would occur", file=sys.stderr)
            print(f"  - No files modified", file=sys.stderr)
            return

        # Success summary
        color = Fore.GREEN if self.cli.use_color else ''
        reset = Style.RESET_ALL if self.cli.use_color else ''

        print(f"\n{color}Interpolation complete{reset}", file=sys.stderr)
        print(f"  - Replaced {self.replacements_count} secret reference(s)", file=sys.stderr)
        print(f"  - Accessed {len(self.accessed_records)} unique record(s)", file=sys.stderr)

        # Report defaults used
        if self.used_defaults:
            color = Fore.YELLOW if self.cli.use_color else ''
            print(f"\n{color}Used {len(self.used_defaults)} default value(s){reset}", file=sys.stderr)
            for notation, default in self.used_defaults[:5]:  # Show first 5
                print(f"  - {notation} -> {default}", file=sys.stderr)
            if len(self.used_defaults) > 5:
                print(f"  ... and {len(self.used_defaults) - 5} more", file=sys.stderr)

        # Report warnings
        if self.warnings:
            color = Fore.YELLOW if self.cli.use_color else ''
            print(f"\n{color}Warnings ({len(self.warnings)}){reset}", file=sys.stderr)
            for warning in self.warnings:
                print(f"  - {warning}", file=sys.stderr)

        # Report errors
        if self.errors:
            color = Fore.RED if self.cli.use_color else ''
            print(f"\n{color}Errors ({len(self.errors)}){reset}", file=sys.stderr)
            for error in self.errors:
                print(f"  - {error}", file=sys.stderr)