import org.gradle.kotlin.dsl.`maven-publish`
import org.gradle.kotlin.dsl.signing

group = "com.keepersecurity.secrets-manager.aws"
version = "1.0.0"

plugins {
    id ("java");
    kotlin("jvm") version "2.0.20"
    kotlin("plugin.serialization") version "2.0.20"
    `maven-publish`
    signing
    id("com.github.johnrengelman.shadow") version "7.1.2"
}
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(11)) 
    }
}

repositories {
    mavenCentral()
}

dependencies {
	implementation("com.keepersecurity.secrets-manager:core:17.0.0")
	implementation ("software.amazon.awssdk:kms:2.20.28")
    implementation ("software.amazon.awssdk:auth:2.20.28")
	implementation("com.fasterxml.jackson.core:jackson-databind:2.18.2")
	implementation("com.fasterxml.jackson.core:jackson-core:2.18.2")
	implementation("com.google.code.gson:gson:2.12.1")
    implementation("org.slf4j:slf4j-api:1.7.32"){
        exclude("org.slf4j:slf4j-log4j12")
    }
	implementation("ch.qos.logback:logback-classic:1.2.6")
	implementation("ch.qos.logback:logback-core:1.2.6")
}


tasks.register<Jar>("fatJar") {
    manifest {
        attributes(
            "Implementation-Title" to "Keeper Secrets Manager AWS KMS Integration",
            "Implementation-Version" to archiveVersion
        )
    }
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    
}

configurations {
    all {
        
    }
}

java {
    withJavadocJar()
    withSourcesJar()
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

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



