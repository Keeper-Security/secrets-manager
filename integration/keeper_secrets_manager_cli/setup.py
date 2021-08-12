from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

# Get the long description from the README.md file
with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

install_requires = [
    'keeper-secrets-manager-core',
    'click',
    'click_help_colors',
    'jsonpath-rw-ext',
    'colorama',
    'importlib_metadata'
]

# Version set in the keeper_secrets_manager_cli.version file.
setup(
    name="keeper-secrets-manager-cli",
    version="0.0.27",
    description="Command line tool for Keeper Secrets Manager",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Keeper Security",
    author_email="ops@keepersecurity.com",
    url="https://github.com/Keeper-Security/secrets-manager",
    license="MIT",
    keywords="Keeper Password Secrets Manager SDK CLI",
    packages=find_packages(exclude=["tests", "tests.*"]),
    zip_safe=False,
    install_requires=install_requires,
    python_requires='>=3.6',
    project_urls={
        "Bug Tracker": "https://github.com/Keeper-Security/secrets-manager/issues",
        "Documentation": "https://app.gitbook.com/"
                         "@keeper-security/s/secrets-manager/secrets-manager/secrets-manager-command-line-interface",
        "Source Code": "https://github.com/Keeper-Security/secrets-manager",
    },
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
    ],
    entry_points={
        "console_scripts": [
            "ksm=keeper_secrets_manager_cli.__main__:main"
        ]
    }
)
