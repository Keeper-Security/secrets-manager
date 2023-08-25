from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

# Get the long description from the README.md file
with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

install_requires = [
    'keeper-secrets-manager-core>=16.3.5'
]

setup(
    name="keeper-secrets-manager-storage",
    version="1.0.2",
    description="Keeper Secrets Manager SDK helper for managing configurations key-value storage.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Keeper Security",
    author_email="sm@keepersecurity.com",
    url="https://github.com/Keeper-Security/secrets-manager",
    license="MIT",
    keywords="Keeper Password Secrets Manager Storage Key-Value HSM",
    packages=find_packages(exclude=["tests", "tests.*"]),
    zip_safe=False,
    package_data={},
    include_package_data=True,
    install_requires=install_requires,
    python_requires='>=3.6',
    project_urls={
        "Bug Tracker": "https://github.com/Keeper-Security/secrets-manager/issues",
        "Documentation": "https://docs.keeper.io/secrets-manager/secrets-manager/overview",
        "Source Code": "https://github.com/Keeper-Security/secrets-manager",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
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
    ]
)
