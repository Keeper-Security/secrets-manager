plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.9.0"
}

rootProject.name = "hello-secret-kt"

// Build against the local Java SDK source instead of the published artifacts.
// Gradle substitutes com.keepersecurity.secrets-manager:core and :yubikey with these projects.
// Pass -PpublishedCore to use the versions from Maven Central instead.
if (!providers.gradleProperty("publishedCore").isPresent) {
    includeBuild("../../../sdk/java/core")
    includeBuild("../../../sdk/java/yubikey")
}
