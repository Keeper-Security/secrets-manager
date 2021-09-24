# Keeper Secrets Manager

|          |  Test Status                                                                                                | Published Artifacts                                                                                                                                                                                         |
-----------|-------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
JavaScript | ![Javascript](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.js.yml/badge.svg)   | [![NPM](https://img.shields.io/npm/v/@keeper-security/secrets-manager-core?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@keeper-security/secrets-manager-core)    |
Python     | ![Python](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.python.yml/badge.svg)   | [![PyPi](https://img.shields.io/pypi/v/keeper-secrets-manager-core?style=for-the-badge&logo=pypi)](https://pypi.org/project/keeper-secrets-manager-core/)                     |
Java       | ![Java](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.java.yml/badge.svg)       | [![Maven Central](https://img.shields.io/maven-central/v/com.keepersecurity.secrets-manager/core?style=for-the-badge&logo=java)](https://search.maven.org/artifact/com.keepersecurity.secrets-manager/core) |
.NET       | ![.NET](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.dotnet.yml/badge.svg)     | [![Nuget](https://img.shields.io/nuget/v/Keeper.SecretsManager?style=for-the-badge&logo=nuget)](https://www.nuget.org/packages/Keeper.SecretsManager)                                                       |
Ansible    | ![Ansible](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.ansible.yml/badge.svg) | [![Ansible](https://img.shields.io/pypi/v/keeper-secrets-manager-ansible?style=for-the-badge&logo=pypi)](https://pypi.org/project/keeper-secrets-manager-ansible/) |
KSM CLI    | ![CLI](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.cli.yml/badge.svg)         | [![PyPi](https://img.shields.io/pypi/v/keeper-secrets-manager-cli?style=for-the-badge&logo=pypi)](https://pypi.org/project/keeper-secrets-manager-cli/)                                                     |
Go         | ![GoLang](https://github.com/keeper-security/secrets-manager-go/actions/workflows/test.go.yml/badge.svg)    | [![Go](https://img.shields.io/badge/Go-Latest-blue.svg?style=for-the-badge&logo=go&logoColor=white)](https://github.com/Keeper-Security/secrets-manager-go)                                   |

# What is Keeper Secrets Manager?

Keeper Secrets Manager is a component of the Keeper Enterprise platform. It provides your DevOps, IT Security and
software development teams with a fully cloud-based, Zero-Knowledge platform for managing all of your 
infrastructure secrets such as API keys, Database passwords, access keys, certificates and any type of confidential data.

Common use cases for Secrets Manager include:
- Removing hard-coded credentials from source code
- Replacing configuration file secrets
- Pulling secrets into CI/CD systems like Jenkins, GitHub Actions and More
- Protecting access to privileged passwords, API keys and other managed secrets.
- Providing vault access to machines and applications

    
More information about Keeper Secrets Manager, SDKs, tools, and integrations can be found in our [official documentation 
portal](https://docs.keeper.io/secrets-manager/secrets-manager/overview)


# Testing

The automated tests are GitHub workflows found in the .github/workflow directory of this project.

## Python

Due the structure of the repository, Python testing might not be able to find all the modules. You can add the following
to PYTHONPATH

* sdk/python/core
* integration/keeper\_secrets\_manager\_cli
* integration/keeper\_secrets\_manager\_ansible/module

Or in IDE like PyCharm, you can add those directories as Source Folders in the Project Structure.






