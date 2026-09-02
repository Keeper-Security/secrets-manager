# Android Example using KSM Java SDK

This is a minimal Android app that shows the Keeper Secrets Manager Java SDK works on Android.

> **WARNING**: This is a demo application for educational purposes only.
> Do not use this code in production without implementing proper security measures.

## Prerequisites

Before running this example, make sure you have:

1. **Android Studio** (Arctic Fox or newer)
2. **Android SDK** with API level 26 or higher (minSdk requirement)
3. **Keeper Secrets Manager Account**: [Sign up here](https://www.keepersecurity.com/)
4. **One-Time Access Token**: Generate from Keeper Secrets Manager:
   - Log in to Keeper Secrets Manager.
   - Go to your application.
   - Generate a one-time access token.
   - The token format is `US:XXXXXX` or `EU:XXXXXX` (region prefix followed by the token).

## Purpose

This example shows that with proper threading, the SDK works as-is on Android. It uses `InMemoryStorage` and the default `HttpsURLConnection` to keep the configuration as simple as possible.

## What This Example Shows

- The SDK initializes on Android.
- `InMemoryStorage` works (no file I/O required).
- Crypto operations work (AES/GCM, ECDH, ECDSA).
- Network communication works (`HttpsURLConnection`).
- Running SDK calls on a background thread prevents ANR errors.

## Limitations

This example is intentionally minimal. It does not include:

- Encrypted storage (uses `InMemoryStorage`)
- OkHttp (uses the default `HttpsURLConnection`)
- Persisted configuration (config is lost when the app restarts)
- Full error handling

## Quick Start

1. Open the project in Android Studio.
2. Wait for Gradle sync to complete.
3. Click **Run**.
4. Enter your Keeper one-time token.
5. Tap **Initialize**.
6. Wait 2-5 seconds.
7. Tap **Load Secrets**.

## Expected Output

After initialization:
```
✅ Initialized successfully!
Now tap 'Load Secrets'
```

After loading secrets:
```
✅ Secrets loaded successfully!

📊 Found 3 secret(s):

1. My Database Password
   Type: login
   UID: Ue8h6JyWUs7Iu6eY_mha-w
   Password: abc***

2. AWS Keys
   Type: login
   UID: xyz123abc456def789
   Password: Xk7***

3. API Token
   Type: login
   UID: def456ghi789jkl012
   (no password)
```

## Code Overview

`MainActivity.kt` (~150 lines) contains the entire app. The SDK calls require only a background thread:

```kotlin
private fun initializeKsm(token: String) {
    lifecycleScope.launch {
        withContext(Dispatchers.IO) {
            initializeStorage(storage, token)
        }
        statusText.text = "✅ Initialized!"
    }
}

private fun loadSecrets() {
    lifecycleScope.launch {
        val secrets = withContext(Dispatchers.IO) {
            val options = SecretsManagerOptions(storage)
            getSecrets(options)
        }
        displaySecrets(secrets)
    }
}
```

## Project Structure

```
android-example/
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
├── .gitignore
└── app/
    ├── build.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/keeper/minimal/
        │   └── MainActivity.kt
        └── res/
            ├── layout/
            │   └── activity_main.xml
            └── values/
                └── strings.xml
```

Total: 10 files, ~300 lines of code.

## Dependencies

```kotlin
dependencies {
    implementation("com.keepersecurity.secrets-manager:keeper-secrets-manager-core:17.1.2")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
```

The example does not use OkHttp, encryption libraries, or Compose.

## Security Considerations for Production

This example uses simplified implementations for educational purposes. For production apps:

- **Token Storage**: Use Android Keystore or `EncryptedSharedPreferences` instead of in-memory storage.
- **Sensitive Data**: Use biometric authentication before the app displays sensitive data.
- **Network Security**: Implement certificate pinning.
- **Error Handling**: Do not expose internal error details to users.
- **Logging**: Remove all sensitive data from logs before release.
- **Code Obfuscation**: Enable ProGuard/R8 with the appropriate keep rules for the SDK.

## Troubleshooting

### Gradle sync fails

```bash
# File > Invalidate Caches > Restart
```

### SDK location not found

```bash
echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties
```

### App crashes on initialization

Check Logcat for network errors. Make sure the token format starts with a region prefix (for example, `US:` or `EU:`). Make sure the device has an internet connection.

### Loading takes a long time on first run

`SecureRandom.getInstanceStrong()` can take 3-5 seconds on the first call. Subsequent calls are faster. This is expected behavior.

### Config is lost after restart

This is by design. The example uses `InMemoryStorage`, which does not persist the configuration to disk.
