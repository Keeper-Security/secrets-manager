# hello-secret

Sample project demonstrating how to extract shared secrets from Keeper.

Prerequisites:

- Java 8 or higher
- One or more client keys obtained from the owner of the secret. Client keys are one-time use.

Usage:

```.shell
./gradlew run --args="%config_name% %client_key%"

For example: 
./gradlew run --args="config.txt EvdTdbH1xbHuRcja7QG3wMOyLUbvoQgF9WkkrHTdkh8"
```

You need to use client key only once per config name. After config has been initialized, the client key becomes obsolete and can be omitted.

To observe this effect, use the same client key with a new config, emulating the scenario of a malicious user intercepting the client key after it was used once - you would get a "Signature is invalid" error.  


