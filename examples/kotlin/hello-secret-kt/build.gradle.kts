import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.2.10"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // Resolved from ../../../sdk/java/core and ../../../sdk/java/yubikey via includeBuild in settings.gradle.kts
    implementation("com.keepersecurity.secrets-manager:core:17.5.0")
    implementation("com.keepersecurity.secrets-manager:yubikey:1.0.0")

    implementation("org.bouncycastle:bc-fips:2.1.1")
//    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}

// Java 8 bytecode like the SDK, so the bin script runs on any JDK from 8 up and not only on the JDK that built it
java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
    }
}

application {
    mainClass.set("hello.secret.kt.AppKt")
}

// Lets the app read the YubiKey PIN from stdin under `./gradlew run`, which has no console
tasks.named<JavaExec>("run") {
    standardInput = System.`in`
}
