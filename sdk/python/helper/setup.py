from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

# Get the long description from the README.md file
with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

install_requires = [
    'keeper-secrets-manager-core>=16.2.2',
    'pyyaml',
    'iso8601'
]

setup(
    name="keeper-secrets-manager-helper",
    version="1.0.5",
    description="Keeper Secrets Manager SDK helper for managing records.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Keeper Security",
    author_email="sm@keepersecurity.com",
    url="https://github.com/Keeper-Security/secrets-manager",
    license="MIT",
    keywords="Keeper Password Secrets Manager Helper Record",
    packages=find_packages(exclude=["tests", "tests.*"]),
    zip_safe=False,
    package_data={},
    include_package_data=True,
    install_requires=install_requires,
    python_requires='>=3.6',
    project_urls={
        "Bug Tracker": "https://github.com/Keeper-Security/secrets-manager/issues",
        "Documentation": "https://app.gitbook.com/"
                         "@keeper-security/s/secrets-manager/secrets-manager",
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
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ]
)
