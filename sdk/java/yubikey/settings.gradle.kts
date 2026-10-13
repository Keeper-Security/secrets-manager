rootProject.name = "yubikey"

plugins {
    id("org.gradle.toolchains.foojay-resolver") version "0.9.0"
}

@Suppress("UnstableApiUsage")
toolchainManagement {
    jvm {
        javaRepositories {
            repository("foojay") {
                resolverClass.set(org.gradle.toolchains.foojay.FoojayToolchainResolver::class.java)
            }
        }
    }
}

// Build against the local Java SDK source instead of the published artifact.
// Gradle substitutes com.keepersecurity.secrets-manager:core with this project.
// Remove this line to use the version from Maven Central.
includeBuild("../core")
