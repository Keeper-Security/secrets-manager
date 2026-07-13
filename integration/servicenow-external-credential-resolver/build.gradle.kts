group = "com.keepersecurity"
version = "1.0.0"

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
    // Pinned (was 16.6.4+, a prefix wildcard that stuck at 16.6.4 and predated the pamSettings
    // KeeperRecordField subtype). 17.x registers all PAM field types and skips unparseable
    // records on a full fetch instead of failing the whole batch.
    implementation("com.keepersecurity.secrets-manager:core:17.3.0")

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

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.10.3")
}

tasks.test {
    useJUnitPlatform()
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
