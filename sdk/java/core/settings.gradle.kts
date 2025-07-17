rootProject.name = "core"

plugins {
    // Note: Versions prior to 1.0.0 require Java 8 or later and Gradle 7.6 or later.
    // Versions 1.0.0 and after require Java 17 or later and Gradle 7.6 or later.
    // Upgrade to 1.0.0+ entails moving java-version matrix out of GHA and implementing in Gradle
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
