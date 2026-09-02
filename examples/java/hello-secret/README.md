# Keeper Secrets Manager Java SDK Example

Sample project that shows how to extract shared secrets from Keeper.

Prerequisites:

- Java 8 or higher
- One or more one-time access tokens from the owner of the shared secret.

Usage:

```.shell
./gradlew run --args="%config_name% %one_time_token%"
```

For example: 
```
./gradlew run --args="config.json US:EvdTdbH1xbHuRcja7QG3wMOyLUbvoQgF9WkkrHTdkh8"
```

The SDK uses the One-Time Access Token once to initialize its configuration. After initialization, you can remove the token.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/java-sdk
