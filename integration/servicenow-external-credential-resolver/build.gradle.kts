group "com.keepersecurity"
version "0.1.0"

plugins {
    base
    java
}

base {
    archivesName = "keeper-external-credentials"
}

java {
    toolchain {
        // Vancouver-- built with OpenJDK 11.x
        languageVersion = JavaLanguageVersion.of(11)

        // Washington DC: A ServiceNow build of OpenJDK 17.0.8.1 is Supported and Included (17.0.8.1-sncmid1)
        // Administrators will need to make sure any 3rd party JAR files for Credential resolvers, JDBC drivers, etc.
        // are compatible with Java 17 and 'strong encapsulation', before upgrading.
        // More information: KB1273036 MID Server - JRE 17 Upgrade

        // Washington DC, Xanadu++ built with OpenJDK 17.x
        //languageVersion = JavaLanguageVersion.of(17)
    }
}

// This must point to the MID Server installation location (agent directory path).
val midServerAgentDir = "/opt/servicenow/mid/agent/lib"

repositories {
    mavenCentral()
    flatDir {
        dirs(midServerAgentDir)
    }
}

dependencies {
    implementation ("com.keepersecurity.secrets-manager:core:16.6.4+")

    // MID server dependencies, not required to be uploaded
    // MID jar dependency for config APIs
    compileOnly("com.snc:mid")
    compileOnly("com.snc:commons-glide")
    compileOnly("com.snc:commons-core-automation")
    compileOnly("com.snc:snc-automation-api")

    // NB! JDK16+/Vancouver+ may require: export _JAVA_OPTIONS="--add-opens=java.base/sun.security.util=ALL-UNNAMED"
    // Vancouver and newer: IFileSystem is in the new mid-api.jar
    if (file("${midServerAgentDir}/mid-api.jar").exists()) {
        compileOnly("com.snc:mid-api")
    }
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes("Main-Class" to "com.snc.discovery.CredentialResolver")
    }
    from(configurations
        .runtimeClasspath
        .get()  // Gradle 6+
        .files  // Gradle 6+
        .map { if (it.isDirectory) it else zipTree(it) }
    )
    exclude("META-INF/*.SF")
    exclude("META-INF/*.DSA")
    exclude("META-INF/*.RSA")
}
