# Keeper Secrets Manager Java SDK Example

Sample project demonstrating how to extract shared secrets from Keeper.

Prerequisites:

- Java 8 or higher
- One or more one-time access tokens obtained from the owner of the secret.

Usage:

```.shell
./gradlew run --args="%config_name% %one_time_token%"
```

For example: 
```
./gradlew run --args="config.json US:EvdTdbH1xbHuRcja7QG3wMOyLUbvoQgF9WkkrHTdkh8"
```

The One-Time Access Token is used once to initialize the SDK configuration. After the SDK configuration is initialized, the One-Time Access Token can be removed.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/java-sdk
