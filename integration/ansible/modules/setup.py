import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
os.chdir(here)

install_requires = [
    'keepercommandersm',
    'ansible'
]

setup(
    name="keeper_ansible",
    version='0.0.1',
    description="Base plugin for Keeper Security related Ansible plugins.",
    author="Keeper Security",
    author_email="ops@keepersecurity.com",
    url="https://github.com/Keeper-Security/secrets-manager",
    license="MIT",
    keywords="Keeper Password Manager SDK Ansible",
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
        "Development Status :: 1 - Planning",
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
