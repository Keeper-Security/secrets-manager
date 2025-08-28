import org.gradle.api.publish.maven.MavenPublication
import org.gradle.kotlin.dsl.`maven-publish`
import org.gradle.kotlin.dsl.signing
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.*

group = "com.keepersecurity.secrets-manager"

// During publishing, If version ends with '-SNAPSHOT' then it will be published to Maven snapshot repository
version = "17.1.1"

plugins {
    `java-library`
    kotlin("jvm") version "2.2.0"
    kotlin("plugin.serialization") version "2.2.0"
    `maven-publish`
    signing
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
    id("org.jreleaser") version "1.18.0"
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
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
    // Use jcenter for resolving dependencies.
    // You can declare any Maven/Ivy/file repository here.
    mavenCentral()
}

dependencies {
    // Align versions of all Kotlin components
    implementation(platform("org.jetbrains.kotlin:kotlin-bom:2.2.0"))

    // Use the Kotlin JDK 8 standard library.
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8:2.2.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    implementation("org.jetbrains.kotlin:kotlin-reflect:2.2.0")

    // Use the Kotlin test library.
    testImplementation("org.jetbrains.kotlin:kotlin-test:2.2.0")

    // Use the Kotlin JUnit integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:2.2.0")

    testImplementation("org.bouncycastle:bc-fips:2.1.1")
//    testImplementation("org.bouncycastle:bcprov-jdk15on:1.70")
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "Keeper Secrets Manager Client Library",
            "Implementation-Version" to archiveVersion
        )
    }
}

ext["signing.keyId"] = null
ext["signing.password"] = null
ext["signing.secretKeyRingFile"] = null
ext["signing.key"] = null
ext["ossrhUsername"] = null
ext["ossrhPassword"] = null

// Grabbing secrets from local.properties file or from environment variables, which could be used on CI
val secretPropsFile = project.rootProject.file("local.properties")
if (secretPropsFile.exists()) {
    // Retrieving variables from the properties file
    val localProperties = Properties()
    localProperties.load(secretPropsFile.inputStream())
    localProperties.forEach { prop -> ext[prop.key.toString()] = prop.value }
} else {
    // Retrieving variables from the properties file
    ext["signing.keyId"] = System.getenv("SIGNING_KEY_ID")
    ext["signing.password"] = System.getenv("SIGNING_PASSWORD")
    ext["signing.secretKeyRingFile"] = System.getenv("SIGNING_SECRET_KEY_RING_FILE")
    ext["signing.key"] = System.getenv("SIGNING_KEY")
    ext["ossrhUsername"] = System.getenv("OSSRH_USERNAME")
    ext["ossrhPassword"] = System.getenv("OSSRH_PASSWORD")
}

java {
    withJavadocJar()
    withSourcesJar()
}

fun getExtraString(name: String) = ext[name]?.toString()

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = project.rootProject.name
            from(components["java"])
            versionMapping {
                usage("java-api") {
                    fromResolutionOf("runtimeClasspath")
                }
                usage("java-runtime") {
                    fromResolutionResult()
                }
            }

            pom {
                name.set("Keeper Secrets Manager")
                description.set("Keeper Secrets Manager is a component of the Keeper Enterprise platform. " +
                        "It provides your DevOps, IT Security and software development teams with a fully cloud-based, " +
                        "Zero-Knowledge platform for managing all of your infrastructure secrets such as API keys, " +
                        "Database passwords, access keys, certificates and any type of confidential data.")
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
                    developer {
                        id.set("MaksimUstinov")
                        name.set("Maksim Ustinov")
                        email.set("mustinov@keepersecurity.com")
                    }
                }
                contributors {
                    contributor {
                        name.set("Craig Lurey")
                        url.set("https://github.com/craiglurey")
                    }
                    contributor {
                        name.set("Sergey Aldoukhov")
                        url.set("https://github.com/saldoukhov")
                    }
                    contributor {
                        name.set("Maksim Ustinov")
                        url.set("https://github.com/maksimu")
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
            name = "Staging"


            if (project.version.toString().endsWith("SNAPSHOT")) {
                setUrl("https://s01.oss.sonatype.org/content/repositories/snapshots/")
            } else {
                setUrl("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            }

            credentials {
                username = getExtraString("ossrhUsername")
                password = getExtraString("ossrhPassword")
            }
        }
    }
}

signing {
    sign(publishing.publications["mavenJava"])
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}

// Task to copy all runtime dependencies for SBOM generation
tasks.register<Copy>("copyDependencies") {
    from(configurations.runtimeClasspath)
    into(layout.buildDirectory.dir("sbom-deps"))
}

// Configure nexusPublishing for staging repository
nexusPublishing {
    repositories {
        create("sonatype") {
            nexusUrl = uri("https://s01.oss.sonatype.org/service/local/")
            snapshotRepositoryUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")

            username = getExtraString("ossrhUsername")
            password = getExtraString("ossrhPassword")
        }
    }
}

// Configure JReleaser for Central Portal publishing
configure<org.jreleaser.gradle.plugin.JReleaserExtension> {
    project {
        copyright = "Keeper Security Inc."
        description = "Keeper Secrets Manager Core SDK for Java"
        inceptionYear = "2022"
        authors.add("Keeper Security Inc.")
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
}
