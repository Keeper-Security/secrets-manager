package hello.secret.kt

import com.keepersecurity.secretsManager.core.*
import com.keepersecurity.secretsManager.yubikey.PinPolicy
import com.keepersecurity.secretsManager.yubikey.PinProvider
import com.keepersecurity.secretsManager.yubikey.YubiKeyException
import com.keepersecurity.secretsManager.yubikey.YubiKeySigner
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
//import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.security.Security
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    val flags = args.filter { it.startsWith("--") }.toSet()
    val positional = args.filter { !it.startsWith("--") }
    if (positional.isEmpty()) {
        println("Usage: ./gradlew run --args=\"%config_name% %one_time_token% [--yubikey]\"")
        println("F.e. ./gradlew run --args=\"config.json US:EXAMPLE_ONE_TIME_TOKEN\"")
        println("Use %one_time_token% only once to initialize the config. For subsequent runs, ./gradlew run --args=%config_name%")
        println("--yubikey generates the client key in a free PIV slot of the connected YubiKey instead of storing it in the config")
        println("--unattended with --yubikey and a One-Time Token: the YubiKey key needs no PIN (PIN policy NEVER)")
        return
    }

    println("Java ${System.getProperty("java.version")} (${System.getProperty("java.vendor")})")

    Security.addProvider(BouncyCastleFipsProvider())
//    Security.addProvider(BouncyCastleProvider())

    val configFile = File(positional[0])
    val storage: KeyValueStorage = LocalConfigStorage(positional[0])
    if (configFile.exists()) {
        println("Local Config Storage opened from the file ${configFile.path}")
    } else {
        println("The file ${configFile.path} does not exist yet, it is created once a One-Time Token initializes the storage")
    }
    val oneTimeToken = positional.getOrNull(1)
    if (oneTimeToken == null && storage.getString(KEY_CLIENT_ID) == null) {
        System.err.println("Error: ${configFile.path} is not initialized, pass a One-Time Token to initialize it")
        exitProcess(1)
    }
    // A config bound to a YubiKey key has a client id but no private key
    val useYubiKey = "--yubikey" in flags ||
            (storage.getString(KEY_CLIENT_ID) != null && storage.getString(KEY_PRIVATE_KEY) == null)
    try {
        if (useYubiKey) {
            // Asked for only when the YubiKey requires it, so keys generated with --unattended never prompt
            val pin = PinProvider { readPin() }
            val unattended = "--unattended" in flags
            val signer = if (storage.getString(KEY_CLIENT_ID) == null) {
                if (unattended) YubiKeySigner() else YubiKeySigner(pin)
            } else {
                // Each config keeps the public key of its YubiKey key, which identifies the slot
                val publicKey = storage.getBytes(KEY_PUBLIC_KEY)
                    ?: throw SecretsManagerException("${configFile.path} has no publicKey, initialize a new config with a One-Time Token")
                val location = storage.getString(KEY_PRIVATE_KEY_LOCATION)
                try {
                    YubiKeySigner.forPublicKey(pin, publicKey)
                } catch (e: YubiKeyException) {
                    throw if (location != null) YubiKeyException("${e.message}. The key of ${configFile.path} is on: $location", e) else e
                }
            }
            signer.use {
                println("YubiKey PIV ${signer.version}")
                if (signer.slot == null) {
                    val pinPolicy = if (unattended) PinPolicy.NEVER else PinPolicy.DEFAULT
                    val publicKey = signer.generateKey(managementKey(), pinPolicy)
                    println("Generated an ECC P-256 key${if (unattended) " that needs no PIN" else ""} in the YubiKey slot ${signer.slot}")
                    // The region prefix of the token (US:, EU:, ...) selects the Keeper host
                    initializeStorage(storage, oneTimeToken!!, null, publicKey)
                    println("Local Config Storage initialized with the One-Time Token")
                } else {
                    println("Using the key on ${signer.keyLocation}")
                    // The SDK reports only the class name of a signer failure, so check the PIN here to keep the retries left in the message
                    signer.verifyPin()
                }
                // The SDK keeps the app key only wrapped by the YubiKey, and names the slot after the application at binding
                printSecrets(SecretsManagerOptions(storage, signer = signer, appKeyProtector = signer))
            }
        } else {
            if (oneTimeToken != null) {
                // The region prefix of the token (US:, EU:, ...) selects the Keeper host
                initializeStorage(storage, oneTimeToken)
                println("Local Config Storage initialized with the One-Time Token")
            }
            printSecrets(SecretsManagerOptions(storage))
        }
    } catch (e: Exception) {
        System.err.println("Error: ${e.message}")
        exitProcess(1)
    }
}

private fun printSecrets(options: SecretsManagerOptions) {
    val secrets = getSecrets(options)
    println("Retrieved ${secrets.records.size} record(s)")

    for (record in secrets.records) {
        println()
        println("${record.recordUid}  ${record.getTitle()}  [${record.getType()}]")
        println("  password: ${if (record.getPassword() != null) "set" else "none"}")
        record.files?.forEach { println("  file: ${it.data.name}") }
    }
}

// Hidden prompt when there is a console; `./gradlew run` has none, so fall back to stdin. The PIN is never read from
// an environment variable or the config: either would leave it where other processes and backups can read it.
private fun readPin(): CharArray {
    System.console()?.let { console ->
        return console.readPassword("YubiKey PIV PIN: ") ?: throw SecretsManagerException("No PIN entered")
    }
    print("YubiKey PIV PIN (no console, input is visible): ")
    System.out.flush()
    return readLine()?.toCharArray() ?: throw SecretsManagerException("No PIN entered")
}

// KSM_YUBIKEY_MGMT_KEY: the PIV management key in hex, if changed from the factory default
private fun managementKey(): ByteArray {
    val hex = System.getenv("KSM_YUBIKEY_MGMT_KEY") ?: return YubiKeySigner.DEFAULT_MANAGEMENT_KEY
    return ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
