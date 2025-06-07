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
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    // Core Keeper Secrets Manager dependency
    implementation("com.keepersecurity.secrets-manager:core:17.0.0")
    
    // Google Cloud KMS dependencies
    implementation("com.google.cloud:google-cloud-kms:2.62.0")
    implementation("com.google.auth:google-auth-library-oauth2-http:1.33.1")
    
    // JSON processing
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
            "Implementation-Title" to "Keeper Secrets Manager GCP KMS Storage",
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
                name.set("Keeper Secrets Manager GCP KMS Storage")
                description.set("GCP KMS storage provider for Keeper Secrets Manager. " +
                        "Provides secure storage of KSM configuration using Google Cloud Key Management Service. " +
                        "Supports symmetric, asymmetric, and raw symmetric encryption.")
                url.set("https://github.com/Keeper-Security/secrets-manager")
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("MaksimUstinov")
                        name.set("Maksim Ustinov")
                        email.set("mustinov@keepersecurity.com")
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
        description = "GCP KMS storage provider for Keeper Secrets Manager"
        authors = listOf("Keeper Security Inc.")
        license = "MIT"
        inceptionYear = "2024"
    }
    
    gitRootSearch = true
    
    signing {
        active = org.jreleaser.model.Active.ALWAYS
        armored = true
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
    // Use JUnit Platform for unit tests.
    useJUnitPlatform()
}
