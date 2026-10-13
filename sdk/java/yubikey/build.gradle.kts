import org.gradle.api.publish.maven.MavenPublication
import org.gradle.kotlin.dsl.`maven-publish`
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

group = "com.keepersecurity.secrets-manager"

// During publishing, If version ends with '-SNAPSHOT' then it will be published to Maven snapshot repository
version = "1.0.0"

plugins {
    `java-library`
    kotlin("jvm") version "2.2.10"
    `maven-publish`
    id("org.jreleaser") version "1.20.0"
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
    withJavadocJar()
    withSourcesJar()
}

tasks.withType<JavaCompile>().configureEach {
    javaCompiler.set(javaToolchains.compilerFor {
        languageVersion.set(JavaLanguageVersion.of(8))
    })
}

kotlin {
    jvmToolchain(8)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // RequestSigner and initializeStorage(publicKey) first ship in core 17.5.0
    api("com.keepersecurity.secrets-manager:core:17.5.0")

    testImplementation("org.jetbrains.kotlin:kotlin-test:2.2.10")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:2.2.10")
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "Keeper Secrets Manager YubiKey Signer",
            "Implementation-Version" to archiveVersion
        )
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = project.rootProject.name
            from(components["java"])

            pom {
                name.set("Keeper Secrets Manager YubiKey Signer")
                description.set("YubiKey PIV support for Keeper Secrets Manager. " +
                        "Generates the client P-256 key on a YubiKey and signs requests with it, " +
                        "so the private key never leaves the device.")
                url.set("https://github.com/Keeper-Security/secrets-manager")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("SergeyAldoukhov")
                        name.set("Sergey Aldoukhov")
                        email.set("saldoukhov@keepersecurity.com")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/Keeper-Security/secrets-manager.git")
                    url.set("https://github.com/Keeper-Security/secrets-manager")
                }
            }
        }
    }

    repositories {
        maven {
            name = "staging"
            url = uri(layout.buildDirectory.dir("staging-deploy"))
        }
    }
}

// Configure JReleaser for Central Portal publishing
jreleaser {
    project {
        copyright = "Keeper Security Inc."
        description = "YubiKey PIV signer for Keeper Secrets Manager"
        inceptionYear = "2026"
        authors = listOf("Keeper Security Inc.")
        license = "MIT"
        links {
            homepage = "https://github.com/Keeper-Security/secrets-manager"
        }
    }

    gitRootSearch = true

    signing {
        active = org.jreleaser.model.Active.ALWAYS
        armored = true
        mode = org.jreleaser.model.Signing.Mode.FILE
    }

    deploy {
        maven {
            mavenCentral {
                create("sonatype") {
                    active = org.jreleaser.model.Active.ALWAYS
                    url = "https://central.sonatype.com/api/v1/publisher"
                    stagingRepository(layout.buildDirectory.dir("staging-deploy").get().asFile.path)
                }
            }
        }
    }

    release {
        github {
            enabled = false
        }
    }
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}
