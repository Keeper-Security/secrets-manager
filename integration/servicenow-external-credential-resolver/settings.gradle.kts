rootProject.name = "keeper-external-credentials"

plugins {
    id("org.gradle.toolchains.foojay-resolver") version "0.8.0"
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
