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

// Development builds compile against the local core source, so this module can be tested before the matching
// core release is on Maven Central. Release builds must use the published core: pass -PpublishedCore.
if (!providers.gradleProperty("publishedCore").isPresent) {
    includeBuild("../core")
}
