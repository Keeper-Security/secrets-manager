plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "com.keeper.minimal"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.keeper.minimal"
        minSdk = 26  // For java.time support
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    // Keeper Secrets Manager SDK - From Maven Central
    implementation("com.keepersecurity.secrets-manager:core:17.1.2")

    // BouncyCastle - Required for EC crypto operations
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // Kotlinx Serialization (required by KSM SDK)
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")

    // Minimal Android dependencies
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")

    // Lifecycle for lifecycleScope
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")

    // Kotlin coroutines for background threading
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
