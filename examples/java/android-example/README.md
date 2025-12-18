# Android Example using KSM Java SDK

**The absolute simplest Android app to prove the Keeper Secrets Manager Java SDK works on Android.**

> **WARNING: This is a DEMO application for educational purposes only.
> Do NOT use this code in production without implementing proper security measures.**

## Prerequisites

Before running this example, ensure you have:

1. **Android Studio** (Arctic Fox or newer recommended)
2. **Android SDK** with API level 26+ (minSdk requirement)
3. **Keeper Secrets Manager Account** - [Sign up here](https://www.keepersecurity.com/)
4. **One-Time Access Token** - Generate from Keeper Secrets Manager:
   - Log into Keeper Secrets Manager
   - Navigate to your application
   - Generate a one-time access token
   - The token format is: `US:XXXXXX` or `EU:XXXXXX` (region prefix + token)

## 🎯 Purpose

This is the **minimal working example** mentioned in the Android Compatibility Analysis. It demonstrates that with just proper threading, the SDK works as-is on Android.

## ⚡ What This Proves

✅ **SDK works on Android** with minimal changes
✅ **InMemoryStorage works** (no file I/O issues)
✅ **Crypto operations work** (AES/GCM, ECDH, ECDSA)
✅ **Network communication works** (HttpsURLConnection)
✅ **No ANR with proper threading** (Coroutines)

## 📦 What's Included

**This is intentionally minimal:**
- ❌ No encrypted storage (uses `InMemoryStorage`)
- ❌ No OkHttp (uses default `HttpsURLConnection`)
- ❌ No fancy UI (simple XML layout)
- ❌ Config not persisted (lost on app restart)
- ❌ Minimal error handling

## 🚀 Quick Start

### 1. Open Project in Android Studio (30 seconds)

### 2. Wait for Gradle Sync (2 minutes)

Let Android Studio download dependencies.

### 3. Run (30 seconds)

Click the green ▶️ Run button.

### 4. Test (1 minute)

1. Enter your Keeper one-time token
2. Tap "1️⃣ Initialize"
3. Wait 2-5 seconds
4. Tap "2️⃣ Load Secrets"
5. See your secrets!

**Total time: ~4 minutes** ⚡

## 📋 What You'll See

### After Initialize:
```
✅ Initialized successfully!
Now tap 'Load Secrets'
```

### After Load Secrets:
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

## 🔍 Code Overview

### MainActivity.kt (~150 lines)

The entire app in one file:

```kotlin
// Initialize KSM
private fun initializeKsm(token: String) {
    lifecycleScope.launch {
        withContext(Dispatchers.IO) {
            // SDK call - works as-is!
            initializeStorage(storage, token)
        }
        statusText.text = "✅ Initialized!"
    }
}

// Load secrets
private fun loadSecrets() {
    lifecycleScope.launch {
        val secrets = withContext(Dispatchers.IO) {
            val options = SecretsManagerOptions(storage)
            getSecrets(options)  // SDK call - works!
        }
        displaySecrets(secrets)
    }
}
```

**That's it!** The SDK works with just proper threading.

## 📊 Project Structure

```
android-example/
├── build.gradle.kts              # Root config
├── settings.gradle.kts           # Project settings
├── gradle.properties
├── .gitignore
│
└── app/
    ├── build.gradle.kts          # Dependencies (minimal!)
    ├── src/main/
    │   ├── AndroidManifest.xml   # Permissions
    │   ├── java/com/keeper/minimal/
    │   │   └── MainActivity.kt   # THE ENTIRE APP (150 lines)
    │   └── res/
    │       ├── layout/
    │       │   └── activity_main.xml  # Simple UI
    │       └── values/
    │           └── strings.xml
```

**Total files: 10**
**Total code: ~300 lines**

## 🔧 Dependencies

**Minimal - only what's needed:**

```kotlin
dependencies {
    // The SDK - REQUIRED
    implementation("com.keepersecurity.secrets-manager:keeper-secrets-manager-core:17.1.2")

    // Basic Android UI
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")

    // Coroutines for background threading
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
```

**That's all!** No OkHttp, no encryption libraries, no compose.

## ✅ What Works

- ✅ SDK initialization
- ✅ Fetching secrets
- ✅ Displaying secrets
- ✅ Password retrieval
- ✅ All crypto operations
- ✅ Network communication
- ✅ Runs on Android 8.0-16 (API 26-36)

## ❌ What Doesn't Work / Limitations

Since this is **intentionally minimal**:

1. **No persistence** - Config lost on app restart (uses `InMemoryStorage`)
2. **Not optimized** - Uses `HttpsURLConnection` (battery drain)
3. **No encryption** - Storage not encrypted (just in-memory)
4. **Minimal error handling** - Basic try/catch only
5. **Simple UI** - No Material3, no fancy design
6. **No offline support** - Requires network for everything


## Security Considerations for Production

This example intentionally uses simplified implementations for clarity. For production apps:

- **Token Storage**: Use Android Keystore or EncryptedSharedPreferences instead of in-memory storage
- **Token Input**: Consider using biometric authentication before displaying sensitive data
- **Network Security**: Implement certificate pinning
- **Error Handling**: Never expose internal error details to users
- **Logging**: Remove all sensitive data from logs
- **Code Obfuscation**: Enable ProGuard/R8 with appropriate keep rules for the SDK

## 🐛 Troubleshooting

### "Gradle sync failed"
```bash
# File → Invalidate Caches → Restart
```

### "SDK location not found"
```bash
echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties
```

### "App crashes on initialization"
**Check Logcat:**
- Look for network errors
- Verify token format (starts with US:, EU:, etc.)
- Check internet connection

### "Loading takes forever"
**This is expected on first run:**
- `SecureRandom.getInstanceStrong()` can take 3-5 seconds
- Subsequent runs are faster
- This is a known issue (see compatibility analysis)

### "Config lost after restart"
**This is by design:**
- Using `InMemoryStorage` (not persisted)