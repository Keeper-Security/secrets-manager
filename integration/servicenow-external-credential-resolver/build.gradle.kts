group = "com.keepersecurity"
version = "1.0.0"

plugins {
    base
    java
    id("org.cyclonedx.bom") version "2.3.0"
}

base {
    archivesName = "keeper-external-credentials"
}

// Pass -PmidRelease=<release> to select which libs/<release>/ to compile against.
// Defaults to the newest release present under libs/.
val midRelease = (project.findProperty("midRelease") as String?)
    ?: file("libs").listFiles()?.map { it.name }?.sorted()?.lastOrNull()
    ?: error("No MID server libs found under libs/. Run ./gradlew jar -PmidRelease=<release>.")

val midServerAgentDir = file("libs/$midRelease")

// Utah and Vancouver ship OpenJDK 11; Washington DC and newer ship OpenJDK 17.
val javaVersion = when (midRelease) {
    "utah", "vancouver" -> JavaLanguageVersion.of(11)
    else -> JavaLanguageVersion.of(17)
}

java {
    toolchain {
        languageVersion = javaVersion
    }
}

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

    compileOnly("com.snc:mid")
    compileOnly("com.snc:commons-glide")
    compileOnly("com.snc:commons-core-automation")
    compileOnly("com.snc:snc-automation-api")

    // mid-api.jar was introduced in Vancouver; absent in Utah.
    if (file("$midServerAgentDir/mid-api.jar").exists()) {
        compileOnly("com.snc:mid-api")
    }

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.10.3")
}

tasks.test {
    useJUnitPlatform()
}

tasks.named<org.cyclonedx.gradle.CycloneDxTask>("cyclonedxBom") {
    // Only the runtimeClasspath is shipped inside the fat JAR. compileOnly MID server
    // JARs and testImplementation/testRuntimeOnly JUnit deps must not appear in the SBOM.
    includeConfigs.set(listOf("runtimeClasspath"))
}

// Resolver JAR variant (pass with -PresolverVariant=fqcn|legacy):
//   fqcn   -> ServiceNow Yokohama (Patch 7+) and newer : ships the unique
//             com.keepersecurity.secretsManager.CredentialResolver and OMITS the shared
//             com.snc.discovery.CredentialResolver, so Keeper coexists with other vendors'
//             resolvers (which ship that shared class) on the same MID Server.
//   legacy -> Xanadu and older : keeps com.snc.discovery.CredentialResolver (required there).
// Default "legacy" keeps both classes (also convenient for local dev/testing).
val resolverVariant = (project.findProperty("resolverVariant") as String? ?: "legacy").lowercase()

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes("Main-Class" to "com.keepersecurity.secretsManager.CredentialResolver")
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
    // The fqcn variant drops ONLY the shared legacy class (com.snc.discovery.CredentialResolver) so
    // it doesn't clash with other vendors' JARs; the unique com.keepersecurity.secretsManager.* class stays.
    if (resolverVariant == "fqcn") {
        exclude("com/snc/discovery/CredentialResolver.class")
    }
}
