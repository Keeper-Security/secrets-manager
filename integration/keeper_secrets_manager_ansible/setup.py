import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
os.chdir(here)

# Get the long description from the README.md file
with open(os.path.join(here, 'README.md'), "r", encoding='utf-8') as fp:
    long_description = fp.read()

install_requires = [
    'keeper-secrets-manager-core>=16.2.2',
    'keeper-secrets-manager-helper>=1.0.4',
    'importlib_metadata',
    'ansible'
]

setup(
    name="keeper-secrets-manager-ansible",
    version='1.1.2',
    description="Keeper Secrets Manager plugins for Ansible.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Keeper Security",
    author_email="ops@keepersecurity.com",
    url="https://github.com/Keeper-Security/secrets-manager",
    license="MIT",
    keywords="Keeper Secrets Manager SDK Ansible",
    packages=find_packages(exclude=["tests", "tests.*"]),
    zip_safe=False,
    install_requires=install_requires,
    python_requires='>=3.6',
    project_urls={
        "Bug Tracker": "https://github.com/Keeper-Security/secrets-manager/issues",
        "Documentation": "https://app.gitbook.com/@keeper-security/s/secrets-manager/secrets-manager/"
                         "integrations/ansible-plugin",
        "Source Code": "https://github.com/Keeper-Security/secrets-manager",
    },
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Systems Administration"
    ],
    entry_points={
        "console_scripts": [
            "keeper_ansible=keeper_secrets_manager_ansible.__main__:main"
        ]
    }
)
