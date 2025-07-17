rootProject.name = "core"

plugins {
    id("org.gradle.toolchains.foojay-resolver") version "1.0.0"
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
