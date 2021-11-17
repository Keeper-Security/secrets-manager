# Go example

Sample project demonstrating how to extract shared secrets from Keeper using Go SDK

Prerequisites:

- Go 1.16 or higher
- One or more client keys obtained from the owner of the secret. Client keys are one-time use.

Install dependency:

```shell
go get github.com/keeper-security/secrets-manager-go/core
```

Usage:

```shell
go run hello-ksm-read.go
```

You need to use client key only once per config name. After config has been initialized, the client key becomes obsolete and can be omitted.
