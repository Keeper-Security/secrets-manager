from pathlib import Path

import difflib

import pytest


PACKAGE_README = Path(__file__).resolve().parents[1] / "README.md"
COLLECTION_README = (Path(__file__).resolve().parents[1] / "ansible_galaxy" / "keepersecurity"
                     / "keeper_secrets_manager" / "README.md")


@pytest.mark.parametrize("readme", [PACKAGE_README, COLLECTION_README], ids=["package", "collection"])
def test_manual_dependency_installation_includes_certifi_minimum(readme):
    commands = [line for line in readme.read_text(encoding="utf-8").splitlines()
                if "pip install" in line and "keeper-secrets-manager-core" in line]
    assert commands, "{}: document the manual dependency installation".format(readme)
    for command in commands:
        assert "'certifi>=2026.10.19'" in command, "{}: include the certifi minimum".format(readme)


@pytest.fixture(params=[
    ("# Upgrading to 1.5.0\n", "# Changes\n"),
    ("## 1.5.0\n", "## 1.4.0\n"),
], ids=["migration", "changelog"])
def upgrade_section(request):
    readme = COLLECTION_README.read_text(encoding="utf-8")
    start, end = request.param
    assert readme.count(start) == 1
    section = readme.split(start, 1)[1]
    assert section.count(end) == 1
    return section.split(end, 1)[0]


def test_engine_installation_and_upgrade_are_explicit(upgrade_section):
    assert "When pip installs the Python package, it upgrades an unsupported ansible-core" not in upgrade_section
    assert "does not install ansible-core" in upgrade_section
    assert "does not install or upgrade it" in upgrade_section
    assert "explicitly install or upgrade" in upgrade_section.lower()
    assert "same Python environment" in upgrade_section
    assert "ansible-core>=2.15.13,!=2.17.*" in upgrade_section


def test_galaxy_version_mismatch_still_warns_unless_configured_to_error(upgrade_section):
    assert "warning" in upgrade_section
    assert "still runs" in upgrade_section
    assert "`collections_on_ansible_version_mismatch = error`" in upgrade_section


@pytest.mark.parametrize("start, end", [
    ("# Configuration notes\n", "# Upgrading to 1.5.0\n"),
    ("# Upgrading to 1.5.0\n", "# Changes\n"),
    ("## 1.5.0\n", "## 1.4.0\n"),
], ids=["configuration-and-check-mode", "migration", "changelog"])
def test_package_and_collection_readmes_share_the_release_sections(start, end):
    """The PyPI README and the Galaxy README ship separately, so edit these sections in both."""
    sections = []
    for readme in (PACKAGE_README, COLLECTION_README):
        text = readme.read_text(encoding="utf-8")
        assert text.count(start) == 1
        section = text.split(start, 1)[1]
        assert section.count(end) >= 1
        sections.append(section.split(end, 1)[0])
    package, collection = sections
    diff = "\n".join(difflib.unified_diff(package.splitlines(), collection.splitlines(),
                                          "package README", "collection README", lineterm="", n=0))
    assert package == collection, diff
