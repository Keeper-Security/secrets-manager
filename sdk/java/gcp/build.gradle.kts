import org.gradle.kotlin.dsl.`maven-publish`
import org.gradle.kotlin.dsl.signing

group = "com.keepersecurity.secrets-manager.gcp"
version = "1.0.0"
plugins {
    // Apply the java-library plugin for API and implementation separation.
    `java-library`
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {

 	implementation("com.keepersecurity.secrets-manager:core:17.0.0")
	implementation ("com.google.cloud:google-cloud-kms:2.62.0")
	implementation ("com.google.auth:google-auth-library-oauth2-http:1.33.1")

	
	implementation("com.fasterxml.jackson.core:jackson-databind:2.18.2")
	implementation("com.fasterxml.jackson.core:jackson-core:2.18.2")

	implementation("org.slf4j:slf4j-api:1.7.32"){
        exclude("org.slf4j:slf4j-log4j12")
    }
	implementation("ch.qos.logback:logback-classic:1.2.6")
	implementation("ch.qos.logback:logback-core:1.2.6") 	
   	  implementation("com.google.auth:google-auth-library-oauth2-http:1.33.0")
}

// Apply a specific Java toolchain to ease working on different environments.
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of((System.getenv("JAVA_VERSION")?.toInt() ?: 11))
    }
}

tasks.named<Test>("test") {
    // Use JUnit Platform for unit tests.
    useJUnitPlatform()
}
