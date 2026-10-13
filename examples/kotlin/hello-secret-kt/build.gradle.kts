plugins {
    kotlin("jvm") version "2.2.10"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // Resolved from ../../../sdk/java/core and ../../../sdk/java/yubikey via includeBuild in settings.gradle.kts
    implementation("com.keepersecurity.secrets-manager:core:17.4.0")
    implementation("com.keepersecurity.secrets-manager:yubikey:1.0.0")

    implementation("org.bouncycastle:bc-fips:2.1.1")
//    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("hello.secret.kt.AppKt")
}

// Lets the app read the YubiKey PIN from stdin under `./gradlew run`, which has no console
tasks.named<JavaExec>("run") {
    standardInput = System.`in`
}
