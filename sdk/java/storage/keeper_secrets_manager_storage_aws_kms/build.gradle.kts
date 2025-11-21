import org.gradle.api.publish.maven.MavenPublication
import org.gradle.kotlin.dsl.`maven-publish`
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

group = "com.keepersecurity.secrets-manager"

// During publishing, If version ends with '-SNAPSHOT' then it will be published to Maven snapshot repository
version = "1.0.0"

plugins {
    `java-library`
    kotlin("jvm") version "2.0.20"
    kotlin("plugin.serialization") version "2.0.20"
    `maven-publish`
    id("org.jreleaser") version "1.18.0"
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

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // Core Keeper Secrets Manager dependency
    implementation("com.keepersecurity.secrets-manager:core:17.1.1")

    // AWS KMS dependencies
    implementation("software.amazon.awssdk:kms:2.20.28")
    implementation("software.amazon.awssdk:auth:2.20.28")

    // JSON processing
    implementation("com.google.code.gson:gson:2.12.1")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.2")
    implementation("com.fasterxml.jackson.core:jackson-core:2.18.2")

    // Logging - Only API for library consumers
    implementation("org.slf4j:slf4j-api:1.7.32") {
        exclude("org.slf4j:slf4j-log4j12")
    }

    // Test dependencies
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.10.2")
    testImplementation("org.mockito:mockito-core:5.8.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.8.0")

    // Logging implementation for tests only
    testImplementation("ch.qos.logback:logback-classic:1.2.6")
    testImplementation("ch.qos.logback:logback-core:1.2.6")
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "Keeper Secrets Manager AWS KMS Storage",
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
                name.set("Keeper Secrets Manager AWS KMS Storage")
                description.set("AWS Key Management Service storage provider for Keeper Secrets Manager. " +
                        "Provides secure storage of KSM configuration using AWS KMS.")
                url.set("https://github.com/Keeper-Security/secrets-manager")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("KeeperSecurity")
                        name.set("Keeper Security Inc.")
                        email.set("info@keepersecurity.com")
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
configure<org.jreleaser.gradle.plugin.JReleaserExtension> {
    project {
        copyright = "Keeper Security Inc."
        description = "AWS Key Management Service storage provider for Keeper Secrets Manager"
        authors = listOf("Keeper Security Inc.")
        license = "MIT"
        inceptionYear = "2024"
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

tasks.named<Test>("test") {
    useJUnitPlatform()
}
