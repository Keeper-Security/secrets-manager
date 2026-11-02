"""Compatibility for unsafe byte values on older controller runtimes."""

import sys


def ensure_unsafe_bytes_compatibility():
    """Repair the affected legacy reducer without changing working implementations."""
    if sys.version_info[:2] not in ((3, 9), (3, 10)) or hasattr(bytes, "__bytes__"):
        return False

    try:
        from ansible.release import __version__ as ansible_version
    except ImportError:
        return False
    if ansible_version.split(".")[:2] not in (["2", "15"], ["2", "16"]):
        return False

    try:
        from ansible.utils.unsafe_proxy import AnsibleUnsafeBytes
    except ImportError:
        return False
    strip_unsafe = getattr(AnsibleUnsafeBytes, "_strip_unsafe", None)
    if not callable(strip_unsafe) or not isinstance(getattr(strip_unsafe, "__qualname__", None), str):
        return False
    try:
        probe = AnsibleUnsafeBytes(b"")
    except Exception:
        return False
    try:
        strip_unsafe(probe)
    except Exception as error:
        if type(error) is not AttributeError or error.args != (  # pylint: disable=unidiomatic-typecheck
                "'super' object has no attribute '__bytes__'",):
            return False
    else:
        return False

    from functools import wraps

    # Keep the callable metadata used by Ansible's template guard, and reconstruct the same unsafe class.
    @wraps(strip_unsafe)
    def compatible_strip_unsafe(value):
        return memoryview(value).tobytes()

    AnsibleUnsafeBytes._strip_unsafe = compatible_strip_unsafe
    return True
