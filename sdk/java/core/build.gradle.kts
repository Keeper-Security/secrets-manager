import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.bundling.Jar
import org.gradle.kotlin.dsl.`maven-publish`
import org.gradle.kotlin.dsl.signing
import java.util.*

group = "com.keepersecurity.secrets-manager"

// During publishing, If version ends with '-SNAPSHOT' then it will be published to Maven snapshot repository
version = "16.0.0-SNAPSHOT"

plugins {
    `java-library`
    kotlin("jvm") version "1.5.10"
    kotlin("plugin.serialization") version "1.5.10"
    `maven-publish`
    signing
    id("io.github.gradle-nexus.publish-plugin") version "1.1.0"

}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    sourceCompatibility = JavaVersion.VERSION_1_8.toString()
    targetCompatibility = JavaVersion.VERSION_1_8.toString()
    kotlinOptions.jvmTarget = JavaVersion.VERSION_1_8.toString()
}

repositories {
    // Use jcenter for resolving dependencies.
    // You can declare any Maven/Ivy/file repository here.
    mavenCentral()
}

dependencies {
    // Align versions of all Kotlin components
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))

    // Use the Kotlin JDK 8 standard library.
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.2.1")

    implementation(files("libs/bc-fips-1.0.2.1.jar"))

    // Use the Kotlin test library.
    testImplementation("org.jetbrains.kotlin:kotlin-test")

    // Use the Kotlin JUnit integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit")
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "Keeper Secrets Manager Client Library",
            "Implementation-Version" to archiveVersion
        )
    }
}

//val fatJar = task("fatJar", type = Jar::class) {
//    baseName = "${project.name}-fat"
//    manifest {
//        attributes(
//            "Implementation-Title" to "Keeper Secrets Manager Client Library with dependencies",
//            "Implementation-Version" to archiveVersion
//        )
//    }
//    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
//    with(tasks.jar.get() as CopySpec)
//}
//
//tasks {
//    "build" {
//        dependsOn(fatJar)
//    }
//}

ext["signing.keyId"] = null
ext["signing.password"] = null
ext["signing.secretKeyRingFile"] = null
ext["ossrhUsername"] = null
ext["ossrhPassword"] = null

// Grabbing secrets from local.properties file or from environment variables, which could be used on CI
val secretPropsFile = project.rootProject.file("local.properties")

if (secretPropsFile.exists()) {

    // Retrieving variables from the properties file
    secretPropsFile.reader().use {
        Properties().apply {
            load(it)
        }
    }.onEach { (name, value) ->
        ext[name.toString()] = value
    }
} else {

    // Retrieving variables from the properties file
    ext["signing.keyId"] = System.getenv("SIGNING_KEY_ID")
    ext["signing.password"] = System.getenv("SIGNING_PASSWORD")
    ext["signing.secretKeyRingFile"] = System.getenv("SIGNING_SECRET_KEY_RING_FILE")
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
                        email.set("maksim@keepersecurity.com")
                    }
                    developer {
                        id.set("MaksimUstinov")
                        name.set("Maksim Ustinov")
                        email.set("maksim@keepersecurity.com")
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
            name = "Sonatype"


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