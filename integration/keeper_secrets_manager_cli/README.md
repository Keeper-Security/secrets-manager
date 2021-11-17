# Keeper Secrets Manager CLI

## Overview

The Keeper Secrets Manager command line interface, ksm, is a tool to:

* View and update secret records.
* Replace environmental variable, and inline parameters, used by an application or script.
* Manage access to multiple applications.

The full documentation can be found on [GitBook](https://app.gitbook.com/@keeper-security/s/secrets-manager/secrets-manager/secrets-manager-command-line-interface).

## Quick Start

Install, or update, the module.

    $ pip install -U keeper-secrets-manager-cli

Create a configuration file for your application.

    $ ksm profile init --token XXXXXXXXXXXX
    Added profile _default to INI config file located at /home/my_home/keeper.ini

List your secrets.

    $ ksm secret list
     UID                      Record Type           Title
     ======================== ===================== ===================
     w5cQhGjMzeZOc_x9i4BcmA   login                 My Website
     Atu8tVgMxpB-iO4xT-Vu3Q   bankCard              Save Smart Bank
     A_7YpGBUgRTeDEQLhVRo0Q   file                  Passport Scan
     EG6KdJaaLG7esRZbMnfbFA   databaseCredentials   Main DB Server

Look at one of your secret records.

    $ ksm secret get -u w5cQhGjMzeZOc_x9i4BcmA
    Record: w5cQhGjMzeZOc_x9i4BcmA
     Title:       My Website
     Record type: login

      Field         Value
     ============= ==============
      login         foo
      password      bar
      url           https://localhost
      fileRef
      oneTimeCode

Look at the same record however this time as JSON.

    $ ksm secret get -u w5cQhGjMzeZOc_x9i4BcmA --json
    {
        "uid": "w5cQhGjMzeZOc_x9i4BcmA",
        "title": "My Website",
        "type": "login",
        "fields": [
            {
                "type": "login",
                "value": [
                    "foo"
                ]
            },
            {
                "type": "password",
                "value": [
                    "bar"
                ]
            },
            ...
        ],
        "custom_fields": [],
        "files": []
    }

Launch an application/script with environment variable replacement.

    $ cat << EOF > my_script.sh
    #!/bin/sh
    echo "Login = \${MY_LOGIN}"
    echo "Password = \${MY_PASSWORD}"
    EOF
    $ chmod u+x my_script.sh
  
    $ export MY_LOGIN="keeper://w5cQhGjMzeZOc_x9i4BcmA/field/login"
    $ export MY_PASSWORD="keeper://w5cQhGjMzeZOc_x9i4BcmA/field/password"
    $ ksm exec -- ./my_script.sh
    Login = foo
    Password = bar
