plugins {
    id("org.jetbrains.kotlin.jvm") version "1.5.30-RC"
    application
}

repositories {
    mavenCentral()
    maven("https://s01.oss.sonatype.org/content/groups/public/")
}

dependencies {
    // Align versions of all Kotlin components
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))

    // Use the Kotlin JDK 8 standard library.
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    implementation("com.keepersecurity.secrets-manager:core:16.2.9")

    implementation("org.bouncycastle:bc-fips:1.0.2.1")

//    implementation("org.bouncycastle:bcprov-jdk15on:1.70")

    // Use the Kotlin test library.
    testImplementation("org.jetbrains.kotlin:kotlin-test")

    // Use the Kotlin JUnit integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit")
}

application {
    mainClassName = "hello.secret.kt.AppKt"
}
