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

    def test_required_packages_in_additional_build_steps(self):
        packages = _packages_from_build_steps(self.spec)
        self.assertTrue(
            packages,
            "execution-environment.yml has no packages in "
            "additional_build_steps.prepend_final — at minimum openssh-clients "
            "must be present for AAP to start (KSM-827)",
        )
        for package, reason in REQUIRED_PACKAGES.items():
            with self.subTest(package=package):
                self.assertIn(
                    package,
                    packages,
                    f"execution-environment.yml must include '{package}' in "
                    f"additional_build_steps.prepend_final — {reason} (KSM-827)",
                )
