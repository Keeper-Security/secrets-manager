# Keeper Secrets Manager Java SDK Example in Kotlin

Sample console app that lists the records shared with a Keeper Secrets Manager application.

The project builds against the local Java SDK source in `sdk/java/core` through a Gradle composite build
(`includeBuild` in `settings.gradle.kts`), so SDK changes are picked up without publishing.
To use the released SDK from Maven Central instead, remove the `includeBuild` line.

Prerequisites:

- JDK 17 or higher to run Gradle (the SDK itself compiles with a Java 8 toolchain, which Gradle provisions automatically)
- One or more one-time access tokens obtained from the owner of the secret.

Usage:

```.shell
./gradlew run --args="%config_name% %one_time_token%"
```

For example: 
```
./gradlew run --args="config.json US:EXAMPLE_ONE_TIME_TOKEN"
```

The One-Time Access Token is used once to initialize the SDK configuration. After the SDK configuration is initialized, the One-Time Access Token can be removed:
```
./gradlew run --args="config.json"
```

## YubiKey

Add `--yubikey` to generate the client private key on a connected YubiKey (ECC P-256) instead of storing it in the
config. The key never leaves the YubiKey, and every request is signed by it. Each config gets its own key, in the first
free retired PIV slot (82 to 95), so one YubiKey can hold the keys of up to 20 configs.
See [sdk/java/yubikey](../../../sdk/java/yubikey/README.md).

`./gradlew run` has no console, so the PIN prompt would echo. Install the app and run it directly for a hidden prompt:
```
./gradlew installDist
build/install/hello-secret-kt/bin/hello-secret-kt config-yubikey.json US:EXAMPLE_ONE_TIME_TOKEN --yubikey
build/install/hello-secret-kt/bin/hello-secret-kt config-yubikey.json
```
The app is compiled for Java 8, so the bin script runs on any JDK from 8 up (set `JAVA_HOME` if needed). A config bound to a YubiKey has no `privateKey` but keeps its
`publicKey`. Later runs detect that, find the slot holding the matching key and use it (YubiKey firmware 5.3 or later).
The app key is protected by the YubiKey too: the config keeps only `appKeyWrapped`, encrypted to a key-agreement key in
PIV slot 9D that all configs share, and the SDK unwraps it on the YubiKey (with the PIN) when it runs. At binding,
the config's slot gets a certificate named after the KSM application, so ykman, Yubico Authenticator and Keychain Access show the application title for the key.

The config also records where its key is, e.g. `"privateKeyLocation": "YubiKey 5C NFC FIPS, serial 12345678, PIV slot 82 (RETIRED1)"`;
the serial is printed on the YubiKey. A key created with `--unattended` adds `, unattended (no PIN)`.

Unattended use (services, cron):

- `--unattended`, with `--yubikey` and a One-Time Token, generates a key that needs no PIN. Later runs of that config
  never ask for one.

The SDK never stores the PIN. A key that needs a PIN always asks for it, so run it with a person present.

```
build/install/hello-secret-kt/bin/hello-secret-kt config-unattended.json US:EXAMPLE_ONE_TIME_TOKEN --yubikey --unattended
```

- `KSM_YUBIKEY_MGMT_KEY` (hex) supplies the PIV management key if it was changed from the factory default.

For more information see our official documentation page https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library/java-sdk
