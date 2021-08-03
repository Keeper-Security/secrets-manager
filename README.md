# Keeper Secrets Manager

![Javascript](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.js.yml/badge.svg)
![Python](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.python.yml/badge.svg)
![Java](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.java.yml/badge.svg)
![Ansible](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.ansible.yml/badge.svg)
![CLI](https://github.com/Keeper-Security/secrets-manager/actions/workflows/test.cli.yml/badge.svg)

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






