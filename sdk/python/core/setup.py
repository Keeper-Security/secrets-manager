import os
from codecs import open
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

os.chdir(here)

# Get the long description from the README.md file
with open(os.path.join(here, 'README.md'), "r", encoding='utf-8') as fp:
    long_description = fp.read()

install_requires = [
    'cryptography',
    'pycryptodomex>=3.7.2',
    'requests >= 2.20;python_version >= "3.0"'
]

setup(
    name="keepercommandersm",
    version='0.0.22a',
    description="Keeper Commander Secrets Management for Python 3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Keeper Security",
    author_email="ops@keepersecurity.com",
    url="https://github.com/Keeper-Security/secrets-manager",
    license="MIT",
    keywords="Keeper Password Manager SDK",
    packages=find_packages(exclude=["tests", "tests.*"]),
    zip_safe=False,
    install_requires=install_requires,
    python_requires='>=3.5',
    project_urls={
        "Bug Tracker": "https://github.com/Keeper-Security/secrets-manager/issues",
        "Documentation": "https://github.com/Keeper-Security/secrets-manager",
        "Source Code": "https://github.com/Keeper-Security/secrets-manager",
    },
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
    ],
)
