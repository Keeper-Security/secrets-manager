"""
The ansible-core and Python requirements of the Galaxy collection, the Tower Execution Environment (EE), and the
Python package. The Python package does not declare ansible-core: it is GPL-3.0-or-later, so declaring it makes
pip install it and puts it in the release SBOM. The collection and the EE state the supported range instead.
ANSIBLE_CORE and PYTHON define the supported requirements, and CI_SERIES lists the engine series that CI must cover.
The checks derive from them, so a change that misses a requirement declaration or CI coverage fails here.
"""
from importlib import metadata
from pathlib import Path
import re
import runpy
import shlex
import sys
import types

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version
import pytest
import yaml


# The 2.17 series is end of life, so every declaration excludes it.
ANSIBLE_CORE = SpecifierSet(">=2.15.13,!=2.17.*")
# Python 3.9.0 and 3.9.1 cannot install the cryptography release that the SDK needs.
PYTHON = SpecifierSet(">=3.9.2")
# The supported engine series that the README promises to test.
CI_SERIES = {(2, 15), (2, 16), (2, 18), (2, 19), (2, 20), (2, 21)}

PROJECT_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = PROJECT_DIR.parents[1]
COLLECTION_DIR = PROJECT_DIR / "ansible_galaxy" / "keepersecurity" / "keeper_secrets_manager"
EE_DIR = PROJECT_DIR / "ansible_galaxy" / "tower_execution_environment"
WORKFLOW = REPO_DIR / ".github" / "workflows" / "test.ansible.yml"

ANSIBLE_CORE_NAME = canonicalize_name("ansible-core")
# pip ignores a comment that starts a line or that follows whitespace.
PIP_COMMENT = re.compile(r"(^|\s+)#.*$")
EE_PYTHON_PATH = re.compile(r"^/usr/bin/python3\.(\d+)$")


def lower_bound(specifier_set):
    bounds = [Version(specifier.version) for specifier in specifier_set if specifier.operator == ">="]
    assert len(bounds) == 1, "{} must have exactly one >= clause".format(specifier_set)
    return bounds[0]


@pytest.fixture
def package_metadata(monkeypatch):
    """
    The keyword arguments that setup.py gives to setup(). A stub setuptools records them, so the test does not need
    setuptools and does not leave it imported in the test session.
    """
    calls = []
    stub = types.ModuleType("setuptools")
    stub.setup = lambda **kwargs: calls.append(kwargs)
    stub.find_packages = lambda *args, **kwargs: []
    monkeypatch.setitem(sys.modules, "setuptools", stub)
    monkeypatch.chdir(PROJECT_DIR)
    runpy.run_path(str(PROJECT_DIR / "setup.py"))
    assert len(calls) == 1, "setup.py must call setup() once"
    return calls[0]


def requirement_lines(path):
    """The requirement lines of a pip requirements file, without blank lines, comments, and pip options."""
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = PIP_COMMENT.sub("", raw).strip()
        if line and not line.startswith("-"):
            yield line


def ansible_requirements(lines, source):
    """The ansible-core requirements in lines, in any spelling of the name. The ansible package is an error."""
    found = []
    for line in lines:
        try:
            requirement = Requirement(line)
        except InvalidRequirement as err:
            pytest.fail("{}: {!r} is not a valid requirement: {}".format(source, line, err))
        name = canonicalize_name(requirement.name)
        assert name != "ansible", "{}: require ansible-core, not the ansible community package".format(source)
        if name == ANSIBLE_CORE_NAME:
            found.append(requirement)
    return found


def single_requirement(requirements, source):
    shown = [str(requirement) for requirement in requirements]
    assert len(requirements) == 1, "{}: declare ansible-core exactly once, found {}".format(source, shown)
    requirement = requirements[0]
    assert requirement.marker is None, "{}: the requirement must not depend on a marker: {}".format(source, shown[0])
    assert requirement.url is None, "{}: the requirement must not be a URL: {}".format(source, shown[0])
    return requirement


def ee_definition():
    return yaml.safe_load((EE_DIR / "execution-environment.yml").read_text(encoding="utf-8"))


def probe_versions(*specifier_sets):
    """One version of each ansible-core series, and the versions next to each bound of the specifier sets."""
    probes = {Version("2.{}.0".format(minor)) for minor in range(9, 30)}
    for specifier_set in specifier_sets:
        for specifier in specifier_set:
            release = Version(specifier.version.replace(".*", "")).release + (0, 0)
            major, minor, micro = release[:3]
            probes.update(Version("{}.{}.{}".format(major, minor, patch))
                          for patch in (max(micro - 1, 0), micro, micro + 1, 99))
    return sorted(probes)


@pytest.fixture
def ci_job():
    if not WORKFLOW.exists():
        pytest.skip("the CI workflow is not part of this checkout")
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["test-ansible"]


@pytest.fixture
def ci_entries(ci_job):
    matrix = ci_job["strategy"]["matrix"]
    assert set(matrix) == {"include"}, "use explicit Python/ansible-core pairs for supported-series coverage"
    return matrix["include"]


def test_package_does_not_declare_ansible_core(package_metadata):
    found = ansible_requirements(package_metadata["install_requires"], "setup.py")
    assert not found, "setup.py: remove {}".format([str(requirement) for requirement in found])


def test_collection_requires_ansible():
    runtime = yaml.safe_load((COLLECTION_DIR / "meta" / "runtime.yml").read_text(encoding="utf-8"))
    assert SpecifierSet(runtime["requires_ansible"]) == ANSIBLE_CORE, (
        "meta/runtime.yml: requires_ansible is {!r}, expected {!r}".format(runtime["requires_ansible"],
                                                                          str(ANSIBLE_CORE)))


def test_role_minimum():
    roles = sorted(COLLECTION_DIR.glob("roles/*/meta/main.yml"))
    if not roles:
        pytest.skip("the collection has no roles")
    for meta in roles:
        value = yaml.safe_load(meta.read_text(encoding="utf-8"))["galaxy_info"]["min_ansible_version"]
        # YAML reads an unquoted 2.10 as the number 2.1, so the value must be a quoted string.
        assert isinstance(value, str), "{}: quote min_ansible_version, YAML reads {!r}".format(meta, value)
        assert Version(value) == lower_bound(ANSIBLE_CORE), "{}: min_ansible_version is {}, expected {}".format(
            meta, value, lower_bound(ANSIBLE_CORE))


def test_execution_environment_python():
    """The EE must name its interpreter, because the default python3 of UBI 9 is Python 3.9."""
    interpreter = ee_definition()["dependencies"].get("python_interpreter") or {}
    match = EE_PYTHON_PATH.match(interpreter.get("python_path") or "")
    assert match, "the EE must set dependencies.python_interpreter.python_path to /usr/bin/python3.X"
    minor = int(match.group(1))
    assert minor >= 10, "the EE uses Python 3.{}, and ansible-core 2.16 and later need Python 3.10".format(minor)
    assert interpreter.get("package_system") == "python3.{}".format(minor), (
        "the EE package_system must install the interpreter python3.{}, found {!r}".format(
            minor, interpreter.get("package_system")))


def test_execution_environment_ansible_core_is_inside_the_package_range():
    """The EE may allow fewer ansible-core versions than the package, but never a version that the package excludes."""
    package_pip = ee_definition()["dependencies"]["ansible_core"]["package_pip"]
    requirement = single_requirement(ansible_requirements([package_pip], "EE package_pip"), "EE package_pip")
    allowed = [version for version in probe_versions(ANSIBLE_CORE, requirement.specifier)
               if requirement.specifier.contains(version)]
    assert allowed, "EE package_pip {!r} allows no ansible-core version".format(package_pip)
    outside = [str(version) for version in allowed if not ANSIBLE_CORE.contains(version)]
    assert not outside, "EE package_pip {!r} allows versions that the package excludes: {}".format(
        package_pip, outside)


def test_requirement_files_leave_ansible_core_out():
    """
    The package requirements.txt mirrors install_requires, so it leaves ansible-core out for the same reason.
    ansible-builder installs the EE requirements.txt as it is, so an ansible-core line there overrides the EE's
    ansible_core setting. It also removes only some spellings of the name from the requirements of a collection.
    """
    for path in sorted(PROJECT_DIR.rglob("requirements*.txt")):
        relative = path.relative_to(PROJECT_DIR)
        if any(part.startswith(".") or part in ("build", "dist") for part in relative.parts):
            continue
        found = ansible_requirements(requirement_lines(path), str(relative))
        assert not found, "{}: remove {}".format(relative, [str(requirement) for requirement in found])


def test_installed_ansible_core_is_supported():
    installed = Version(metadata.version("ansible-core"))
    assert installed in ANSIBLE_CORE, "installed ansible-core {} is outside {}".format(installed, ANSIBLE_CORE)


def test_ci_installs_with_the_supported_constraint(ci_job):
    step = next(step for step in ci_job["steps"] if step.get("name") == "Install Ansible dependencies")
    assert step["env"]["ANSIBLE_CORE_SPEC"] == "${{ matrix.ansible-core }}"
    commands = [shlex.split(line) for line in step["run"].splitlines() if line.strip()]
    installs = [command for command in commands
                if command[:4] == ["python3", "-m", "pip", "install"] and "-r" in command]
    assert len(installs) == 1, "install requirements.txt and both engine constraints in one pip command"
    command = installs[0]
    assert command[command.index("-r") + 1] == "requirements.txt"
    assert "$ANSIBLE_CORE_SPEC" in command, "the pip command must use the matrix's engine selection"
    requirements = ansible_requirements([argument for argument in command[4:] if argument.startswith("ansible")],
                                       "CI pip install")
    requirement = single_requirement(requirements, "CI pip install")
    assert requirement.specifier == ANSIBLE_CORE, (
        "CI must constrain ansible-core independently of requirements.txt: expected {}".format(ANSIBLE_CORE))


def test_ci_covers_the_supported_series(ci_entries):
    covered = set()
    python310_covers216 = False
    for entry in ci_entries:
        source = "CI Python {} ({})".format(entry["python-version"], entry["ansible-core"])
        requirement = single_requirement(ansible_requirements([entry["ansible-core"]], source), source)
        allowed = [version for version in probe_versions(ANSIBLE_CORE, requirement.specifier)
                   if version in requirement.specifier]
        assert allowed, "{} allows no engine version".format(source)
        outside = [str(version) for version in allowed if version not in ANSIBLE_CORE]
        assert not outside, "{} allows unsupported engines: {}".format(source, outside)
        series = {version.release[:2] for version in allowed}
        assert len(series) == 1, "{} must select one engine series, found {}".format(source, sorted(series))
        covered.update(series)
        if Version(entry["python-version"]).release[:2] == (3, 10) and series == {(2, 16)}:
            python310_covers216 = True
    assert CI_SERIES <= covered, "CI is missing supported engine series: {}".format(sorted(CI_SERIES - covered))
    assert python310_covers216, "CI must run Python 3.10 with ansible-core 2.16"


def test_ci_runs_the_minimum_and_the_oldest_python(ci_entries):
    pin = "ansible-core=={}".format(lower_bound(ANSIBLE_CORE))
    assert any(entry["ansible-core"] == pin for entry in ci_entries), (
        "the workflow must run {}".format(pin))
    oldest = min((entry["python-version"] for entry in ci_entries), key=Version)
    assert Version(oldest).release[:2] == lower_bound(PYTHON).release[:2], (
        "the oldest CI Python is {}, but python_requires is {}".format(oldest, PYTHON))


def test_ci_covers_the_package_python_versions(package_metadata, ci_entries):
    advertised = set()
    for classifier in package_metadata["classifiers"]:
        match = re.fullmatch(r"Programming Language :: Python :: (\d+\.\d+)", classifier)
        if match:
            advertised.add(Version(match.group(1)).release[:2])
    assert advertised, "setup.py must advertise specific Python versions"
    covered = {Version(entry["python-version"]).release[:2] for entry in ci_entries}
    missing = advertised - covered
    assert not missing, "CI is missing Python versions advertised by setup.py: {}".format(
        ["{}.{}".format(*version) for version in sorted(missing)])


def test_python_requirement(package_metadata):
    """Python 3.9 stays supported in this release. Change PYTHON, the CI matrix, and the README together."""
    assert SpecifierSet(package_metadata["python_requires"]) == PYTHON
