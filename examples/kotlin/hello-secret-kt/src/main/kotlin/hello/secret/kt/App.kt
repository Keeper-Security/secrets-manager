package hello.secret.kt

import com.keepersecurity.secretsManager.core.*
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
//import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.Provider
//import java.security.Security

class App

class TestCryptoProvider : CryptoProvider {

    private val p: Provider = BouncyCastleFipsProvider()
//    private val p: Provider = BouncyCastleProvider()

    override val provider: Provider
        get() = p

    override fun multiplyG(s: BigInteger): ByteArray {
        return ECNamedCurveTable.getByName("secp256r1").g.multiply(s).getEncoded(false)
    }
}

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: ./gradlew run --args=\"%config_name% %client_key%\"")
        println("F.e. ./gradlew run --args=\"config.json US:EXAMPLE_ONE_TIME_TOKEN\"")
        println("Use %client_key% only once to initialize the config. For subsequent runs, ./gradlew run --args=%config_name%")
        return
    }

// If working with initialized config, Secrets Manager does not need to call setCryptoProvider if the client already uses BouncyCastle or BouncyCastle FIPS
// If using one time token, Secrets Manager need to export the public key and needs a call to setCryptoProvider to wire the necessary logic
//    Security.addProvider(BouncyCastleFipsProvider())
//    Security.addProvider(BouncyCastleProvider());
    setCryptoProvider(TestCryptoProvider());

    val storage: KeyValueStorage = LocalConfigStorage(args[0])
    println("Local Config Storage opened from the file ${args[0]}")
    try {
        if (args.size > 1) {
            println("Local Config Storage initialized with the Client Key ${args[1]}")
            // if your Keeper Account is in other region than US, update the hostname accordingly
            initializeStorage(storage, args[1], "keepersecurity.com")
        }
        val options = SecretsManagerOptions(storage)
//        val options = SecretsManagerOptions(storage, cachingPostFunction)
        val (records) = getSecrets(options)
        //            KeeperSecrets secrets = getSecrets(options, Arrays.asList("RECORD_UID"));
        println(records)

        // get the password from the first record
        val firstRecord = records[0]
        val firstRecordPassword = firstRecord.getPassword()
        println(firstRecordPassword)

        // download the file from the 3rd record
        val file = records[2].getFileByName("acme.cer")
        if (file != null) {
            val fileBytes = downloadFile(file)
            FileOutputStream(file.data.name).use { fos -> fos.write(fileBytes) }
        }

        // update the password on the first record
        firstRecord.updatePassword("N3wP4$$w0rd")
        updateSecret(options, firstRecord)
    } catch (e: Exception) {
        println(e.message)
    }
}
