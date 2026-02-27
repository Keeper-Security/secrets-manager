import os
import unittest
import yaml


EE_SPEC_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "ansible_galaxy",
    "tower_execution_environment",
    "execution-environment.yml",
)


# Packages required in the EE that are absent from the redhat/ubi9 base image.
# ansible-runner (the previous base) included these; ubi9 does not.
REQUIRED_PACKAGES = {
    "openssh-clients": "provides ssh-agent required by AAP at container startup",
    "sshpass":         "required for password-based SSH (ansible_ssh_pass)",
    "rsync":           "required by ansible.builtin.synchronize module",
    "git":             "required by ansible.builtin.git module",
}


class TowerExecutionEnvironmentTest(unittest.TestCase):
    """KSM-827: Verify tower EE spec includes required system packages.

    The keeper-secrets-manager-tower-ee image uses redhat/ubi9 as its base.
    UBI9 is a minimal OS image — it does not include the packages that
    ansible-runner (the previous base) provided. Missing packages cause
    runtime failures in AAP that are not caught by the Ansible plugin unit
    tests because those tests never build or run the Docker image.
    """

    def setUp(self):
        with open(EE_SPEC_PATH, "r") as f:
            self.spec = yaml.safe_load(f)

    def test_required_packages_in_additional_build_packages(self):
        packages = self.spec.get("additional_build_packages", [])
        for package, reason in REQUIRED_PACKAGES.items():
            with self.subTest(package=package):
                self.assertIn(
                    package,
                    packages,
                    f"execution-environment.yml must include '{package}' in "
                    f"additional_build_packages — {reason} (KSM-827)",
                )
