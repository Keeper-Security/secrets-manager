plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.9.0"
}

rootProject.name = "hello-secret-kt"

// Build against the local Java SDK source instead of the published artifact.
// Gradle substitutes com.keepersecurity.secrets-manager:core and :yubikey with these projects.
// Remove these lines to use the versions from Maven Central.
includeBuild("../../../sdk/java/core")
includeBuild("../../../sdk/java/yubikey")
