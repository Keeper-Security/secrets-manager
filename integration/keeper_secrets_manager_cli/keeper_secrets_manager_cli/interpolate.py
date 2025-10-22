# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import os
import sys
import re
import json
import logging
from keeper_secrets_manager_cli.exception import KsmCliException
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.keeper_globals import logger_name


class Interpolate:
    """
    Interpolate Keeper notation in text files.

    Reads files, replaces all keeper:// notation with secret values from
    Keeper Secrets Manager, and outputs the result.
    """

    def __init__(self, cli):
        """
        Initialize Interpolate instance.

        Args:
            cli: KeeperCli instance for SDK access
        """
        self.cli = cli
        self.logger = logging.getLogger(logger_name)
        # Cache notation lookups to reduce SDK calls
        self.local_cache = {}

    def _get_secret(self, notation):
        """
        Fetch secret value using notation, with caching.

        Args:
            notation: Keeper notation string (keeper://uid/field/label)

        Returns:
            Secret value as string

        Raises:
            ValueError: If notation is invalid or secret not found
        """
        # If not in the cache, fetch from SDK and cache it
        if notation not in self.local_cache:
            value = self.cli.client.get_notation(notation)
            # Convert dict/list to JSON string
            if type(value) is dict or type(value) is list:
                value = json.dumps(value)
            self.local_cache[notation] = str(value)

        return self.local_cache[notation]

    def _interpolate_content(self, content):
        """
        Replace all keeper:// notation in content string.

        Respects .env file syntax - skips comment lines (lines starting with #).

        Args:
            content: File content as string

        Returns:
            Content with all notation replaced
        """
        # Use SDK constant for consistency with exec.py
        prefix = SecretsManager.notation_prefix
        # Pattern matches keeper notation: keeper://UID/TYPE/NAME
        # UID and TYPE segments cannot contain spaces or slashes
        # NAME segment (field/file name) CAN contain spaces
        # Stops at: quotes, newlines, or # (comment character)
        pattern = rf'{prefix}://[^\s/]+/[^\s/]+/[^"\'\n#]+'

        def replace_notation(match):
            notation = match.group().strip()  # Strip any trailing whitespace
            try:
                return self._get_secret(notation)
            except ValueError as err:
                error_str = str(err)
                # Match error handling pattern from exec.py:54-56
                # Skip invalid notation (might not be actual notation)
                if (error_str.startswith("Invalid format of Keeper notation") or
                    error_str.startswith("Keeper notation is invalid") or
                    error_str.startswith("Keeper url missing") or
                    error_str.startswith("Keeper notation URI missing")):
                    self.logger.info(f"Skipping invalid notation '{notation}': {error_str}")
                    return notation  # Leave original text unchanged
                else:
                    # Unexpected error (network, access denied, etc.)
                    raise KsmCliException(f"Failed to fetch notation '{notation}': {error_str}")

        # Process line by line to respect .env file comment syntax
        lines = content.split('\n')
        processed_lines = []

        for line in lines:
            # Check if line is a comment (starts with # after stripping leading whitespace)
            stripped = line.lstrip()
            if stripped.startswith('#'):
                # Skip processing comments - keep original line
                processed_lines.append(line)
            else:
                # Process non-comment lines for notation replacement
                processed_lines.append(re.sub(pattern, replace_notation, line))

        return '\n'.join(processed_lines)

    def interpolate_file(self, input_path, output_path=None):
        """
        Read file, replace keeper:// notation, output result.

        Args:
            input_path: Path to input file
            output_path: Optional path to write output (stdout if None)

        Raises:
            KsmCliException: On file errors or secret fetch failures
        """
        # Security: Resolve absolute path and follow symlinks
        input_path = os.path.realpath(os.path.abspath(input_path))

        # Security: Check file exists and is a regular file
        if not os.path.isfile(input_path):
            raise KsmCliException(f"File not found: {input_path}")

        # Security: Check file size (10MB limit)
        file_size = os.path.getsize(input_path)
        max_size = 10 * 1024 * 1024  # 10MB
        if file_size > max_size:
            raise KsmCliException(
                f"File too large: {file_size} bytes (limit: {max_size} bytes / 10MB)"
            )

        # Read input file with explicit UTF-8 encoding
        try:
            with open(input_path, 'r', encoding='utf-8', errors='strict') as f:
                content = f.read()
        except UnicodeDecodeError:
            raise KsmCliException(
                f"Cannot read {input_path}: File must be UTF-8 encoded text. "
                "Binary files are not supported."
            )
        except FileNotFoundError:
            raise KsmCliException(f"File not found: {input_path}")
        except PermissionError:
            raise KsmCliException(f"Permission denied: {input_path}")
        except OSError as err:
            raise KsmCliException(f"Error reading file: {err}")

        # Replace all keeper:// notation
        interpolated = self._interpolate_content(content)

        # Output to file or stdout
        if output_path:
            # Security: Resolve output path
            output_path = os.path.realpath(os.path.abspath(output_path))

            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(interpolated)
                # Status message to stderr (won't interfere with pipes)
                sys.stderr.write(f"Interpolated file written to: {output_path}\n")
            except PermissionError:
                raise KsmCliException(f"Permission denied writing to: {output_path}")
            except OSError as err:
                raise KsmCliException(f"Failed to write output file: {err}")
        else:
            # Content to stdout (for eval/source/pipes)
            # Use sys.stdout.write to preserve exact content (no added newlines)
            sys.stdout.write(interpolated)
