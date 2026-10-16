import ast
import unittest
from pathlib import Path

import yaml
from packaging.requirements import Requirement
from packaging.version import Version


INTEGRATION_PATH = Path(__file__).resolve().parents[1]
EE_PATH = INTEGRATION_PATH / "ansible_galaxy" / "tower_execution_environment"
COLLECTION_PATH = (
    INTEGRATION_PATH / "ansible_galaxy" / "keepersecurity" / "keeper_secrets_manager"
)
EE_SPEC_PATH = EE_PATH / "execution-environment.yml"
SDK_PACKAGES = {"keeper-secrets-manager-core", "keeper-secrets-manager-helper"}


def _sdk_minimum_versions(requirements):
    minimums = {}
    for line in requirements:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        if requirement.name not in SDK_PACKAGES:
            continue
        versions = [
            Version(specifier.version)
            for specifier in requirement.specifier
            if specifier.operator == ">="
        ]
        if not versions:
            raise AssertionError(
                f"{requirement.name} must declare a '>=' minimum version"
            )
        minimums[requirement.name] = max(versions)
    return minimums


def _setup_sdk_minimum_versions():
    """Read dependency declarations without executing setup.py."""
    setup_path = INTEGRATION_PATH / "setup.py"
    tree = ast.parse(setup_path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "install_requires"
            for target in node.targets
        ):
            return _sdk_minimum_versions(ast.literal_eval(node.value))
    raise AssertionError("setup.py must declare install_requires")


# Packages required in the EE that are absent from the redhat/ubi9 base image.
# ansible-runner (the previous base) included these; ubi9 does not.
REQUIRED_PACKAGES = {
    "openssh-clients":  "provides ssh-agent required by AAP at container startup",
    "sshpass":          "required for password-based SSH (ansible_ssh_pass)",
    "rsync":            "required by ansible.builtin.synchronize module",
    "git":              "required by ansible.builtin.git module",
    "krb5-workstation": "required for Kerberos auth to Windows hosts (kinit/klist)",
}


def _packages_from_build_steps(spec):
    """Extract package names from additional_build_steps.prepend_final RUN commands.

    The v3 EE schema installs system packages via:
      additional_build_steps:
        prepend_final:
          - RUN $PKGMGR install -y pkg1 pkg2 && $PKGMGR clean all
    """
    packages = []
    steps = (
        spec.get("additional_build_steps", {})
            .get("prepend_final", [])
    )
    for step in steps:
        if not isinstance(step, str):
            continue
        # Strip the RUN prefix and split on whitespace / shell operators
        tokens = step.replace("&&", " ").split()
        in_install = False
        for token in tokens:
            if token in ("install", "-y"):
                in_install = True
                continue
            if in_install:
                # Stop at the next command boundary or pkgmgr invocation
                if token.startswith("$") or token.startswith("-"):
                    in_install = False
                    continue
                packages.append(token)
    return packages


class TowerExecutionEnvironmentTest(unittest.TestCase):
    """Verify EE system packages and SDK dependency floors.

    The keeper-secrets-manager-tower-ee image uses redhat/ubi9 as its base.
    UBI9 is a minimal OS image. It does not include the packages that
    ansible-runner (the previous base) provided. Missing packages cause
    runtime failures in AAP that are not caught by the Ansible plugin unit
    tests because those tests never build or run the Docker image.
    """

    def setUp(self):
        with open(EE_SPEC_PATH, "r", encoding="utf-8") as f:
            self.spec = yaml.safe_load(f)

    def _assert_sdk_minimum_versions(self, requirements_path):
        expected = _setup_sdk_minimum_versions()
        actual = _sdk_minimum_versions(
            requirements_path.read_text(encoding="utf-8").splitlines()
        )
        for package in sorted(SDK_PACKAGES):
            with self.subTest(package=package, requirements=str(requirements_path)):
                self.assertIn(package, expected, f"setup.py must require {package}")
                self.assertIn(
                    package, actual, f"{requirements_path} must require {package}"
                )
                self.assertGreaterEqual(
                    actual[package],
                    expected[package],
                    f"{requirements_path} allows {package} below the "
                    f"setup.py minimum of {expected[package]}",
                )

    def test_ee_sdk_minimum_versions(self):
        self._assert_sdk_minimum_versions(
            EE_PATH / self.spec["dependencies"]["python"]
        )

    def test_collection_sdk_minimum_versions(self):
        self._assert_sdk_minimum_versions(COLLECTION_PATH / "requirements.txt")

    def test_integration_sdk_minimum_versions(self):
        self._assert_sdk_minimum_versions(INTEGRATION_PATH / "requirements.txt")

    def test_required_packages_in_additional_build_steps(self):
        packages = _packages_from_build_steps(self.spec)
        self.assertTrue(
            packages,
            "execution-environment.yml has no packages in "
            "additional_build_steps.prepend_final: at minimum openssh-clients "
            "must be present for AAP to start",
        )
        for package, reason in REQUIRED_PACKAGES.items():
            with self.subTest(package=package):
                self.assertIn(
                    package,
                    packages,
                    f"execution-environment.yml must include '{package}' in "
                    f"additional_build_steps.prepend_final: {reason}",
                )
